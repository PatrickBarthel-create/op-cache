import Darwin
import Foundation

/// What the audit log records, and what it deliberately does not.
///
/// `unlock` is the only command that reaches 1Password, so it is the only
/// place where "which item from which vault" is a real fetch. `run` never
/// touches 1Password; it reads the Keychain and injects values into a child.
/// Recording both gives an injection log: which secret went into which
/// process. It is not an access log — it cannot show what the child did with
/// the value, and `run` without `--only` injects the whole profile whether or
/// not the child reads any of it.
///
/// Values are never written here. Only the `op://` reference, which names the
/// vault, item, and field.
public struct AuditSecret: Codable, Sendable, Equatable {
    public let name: String
    public let reference: String

    public init(name: String, reference: String) {
        self.name = name
        self.reference = reference
    }
}

/// The process that invoked op-cache. Advisory only: any process that can run
/// op-cache can also spawn it from a parent of its choosing.
public struct AuditCaller: Codable, Sendable, Equatable {
    public let pid: Int32
    public let path: String?

    public init(pid: Int32, path: String?) {
        self.pid = pid
        self.path = path
    }

    public static func current() -> AuditCaller {
        let parent = getppid()
        var buffer = [UInt8](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(parent, &buffer, UInt32(MAXPATHLEN))
        guard length > 0 else { return AuditCaller(pid: parent, path: nil) }
        return AuditCaller(pid: parent, path: String(decoding: buffer[..<Int(length)], as: UTF8.self))
    }
}

public struct AuditEvent: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case unlock
        case run
        /// Everlast fork only: an `op` call answered through the shim.
        case proxy
    }

    public let timestamp: Date
    public let event: Kind
    public let profile: String
    public let account: String
    public let secrets: [AuditSecret]
    public let ttl: String?
    public let expiresAt: Date?
    /// The child executable only. Its arguments are never recorded: a command
    /// line is free-form and routinely carries secrets of its own, and an
    /// audit log that leaks them defeats its own purpose.
    public let command: String?
    public let argumentCount: Int?
    /// Proxy events only: the `op` subcommand path, e.g. "item get". Never the
    /// arguments, for the same reason `command` omits them.
    public let subcommand: String?
    /// Proxy events only: how the call was classified, and whether the cache
    /// answered it. Together these show which calls still cost an approval.
    public let cacheKind: String?
    public let cacheHit: Bool?
    public let caller: AuditCaller

    public init(
        timestamp: Date = Date(),
        event: Kind,
        profile: String,
        account: String,
        secrets: [AuditSecret],
        ttl: String? = nil,
        expiresAt: Date? = nil,
        command: String? = nil,
        argumentCount: Int? = nil,
        subcommand: String? = nil,
        cacheKind: String? = nil,
        cacheHit: Bool? = nil,
        caller: AuditCaller = .current()
    ) {
        self.timestamp = timestamp
        self.event = event
        self.profile = profile
        self.account = account
        self.secrets = secrets
        self.ttl = ttl
        self.expiresAt = expiresAt
        self.command = command
        self.argumentCount = argumentCount
        self.subcommand = subcommand
        self.cacheKind = cacheKind
        self.cacheHit = cacheHit
        self.caller = caller
    }
}

public struct AuditConfig: Codable, Sendable, Equatable {
    public var enabled: Bool?
    public var path: String?

    public init(enabled: Bool? = nil, path: String? = nil) {
        self.enabled = enabled
        self.path = path
    }

    public var isEnabled: Bool { enabled ?? true }

    /// Resolved destination, or nil when logging is off.
    public func resolvedURL() -> URL? {
        guard isEnabled else { return nil }
        guard let path, !path.isEmpty else { return AuditLog.defaultURL() }
        return URL(fileURLWithPath: NSString(string: path).expandingTildeInPath)
    }
}

/// Appends one JSON object per line. Failures never block a command: the cache
/// itself is the security boundary, and a log that can be made to fail closed
/// by deleting a file would only hand callers a denial-of-service switch.
public struct AuditLog: Sendable {
    public static let maximumBytes = 5 * 1024 * 1024

    public static func defaultURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/op-cache-audit.jsonl")
    }

    public let url: URL?
    private let warn: @Sendable (String) -> Void

    public init(url: URL?, warn: @escaping @Sendable (String) -> Void = { fputs("op-cache: \($0)\n", stderr) }) {
        self.url = url
        self.warn = warn
    }

    public init(config: AuditConfig?, warn: @escaping @Sendable (String) -> Void = { fputs("op-cache: \($0)\n", stderr) }) {
        self.init(url: (config ?? AuditConfig()).resolvedURL(), warn: warn)
    }

    public func record(_ event: AuditEvent) {
        guard let url else { return }
        do {
            try append(encode(event), to: url)
        } catch {
            warn("could not write the audit log at \(url.path): \(error.localizedDescription)")
        }
    }

    public static func encode(_ event: AuditEvent) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        // Without this, references are written as op:\/\/Vault\/Item, which is
        // valid JSON but defeats grepping the log for an op:// reference.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(event)
        data.append(0x0A)
        return data
    }

    private func encode(_ event: AuditEvent) throws -> Data {
        try Self.encode(event)
    }

    private func append(_ data: Data, to url: URL) throws {
        let manager = FileManager.default
        try manager.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try rotateIfNeeded(at: url)

        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
        guard descriptor >= 0 else {
            throw OpCacheError.message(String(cString: strerror(errno)))
        }
        defer { close(descriptor) }

        // An existing log from an earlier run may be more permissive than the
        // 0600 used at creation. Metadata is all that is at stake, but there
        // is no reason to leave it readable.
        var info = stat()
        if fstat(descriptor, &info) == 0, info.st_mode & 0o077 != 0 {
            _ = fchmod(descriptor, 0o600)
        }

        try data.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                let result = write(descriptor, buffer.baseAddress! + written, buffer.count - written)
                guard result > 0 else {
                    throw OpCacheError.message(String(cString: strerror(errno)))
                }
                written += result
            }
        }
    }

    private func rotateIfNeeded(at url: URL) throws {
        let manager = FileManager.default
        guard let size = try? manager.attributesOfItem(atPath: url.path)[.size] as? NSNumber,
              size.intValue >= Self.maximumBytes else { return }
        let rotated = url.appendingPathExtension("1")
        try? manager.removeItem(at: rotated)
        try manager.moveItem(at: url, to: rotated)
    }
}
