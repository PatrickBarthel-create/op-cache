import Darwin
import Foundation

/// Answers `op` invocations from cache where that is safe, and forwards the
/// rest untouched.
///
/// Everlast fork only. The upstream model is a curated allowlist: you name the
/// secrets in advance and reach them through `op-cache run`. Measured over 30
/// days on this machine that allowlist answered 65 calls while 4,246 went
/// straight to `op`, one biometric approval each. The friction was the reason:
/// `op read op://…` is what gets typed, so the cache sat idle and the approval
/// prompt lost all meaning through sheer repetition.
///
/// This trades a curated allowlist for a self-populating one. Anything fetched
/// once is served from cache until its TTL expires. That is a real widening —
/// during the window any process running as this user can read those values
/// without an approval — bounded by the measured working set, which was 34
/// distinct references over three days rather than the whole vault.
public struct ProxyRunner: Sendable {
    /// Keychain profile holding proxied secret results. Underscore-prefixed so
    /// it cannot collide with a user profile, whose names must start with a
    /// letter or underscore and are validated on load.
    public static let profileName = "_proxy"

    /// Larger results are forwarded but not cached: the Keychain is a poor
    /// store for blobs, and no credential is anywhere near this size.
    public static let maximumSecretBytes = 64 * 1024

    private let onePassword: OnePassword
    private let keychain: KeychainStore
    private let meta: MetaCache
    private let items: ItemStore
    private let resolver: ItemResolver
    private let audit: AuditLog
    private let ttl: TimeInterval
    private let ttlText: String
    private let lockDirectory: URL

    public init(
        onePassword: OnePassword = OnePassword(),
        keychain: KeychainStore = KeychainStore(),
        meta: MetaCache = MetaCache(),
        items: ItemStore = ItemStore(),
        resolver: ItemResolver = ItemResolver(),
        audit: AuditLog,
        ttl: TimeInterval,
        ttlText: String,
        lockDirectory: URL? = nil
    ) {
        self.onePassword = onePassword
        self.keychain = keychain
        self.meta = meta
        self.items = items
        self.resolver = resolver
        self.audit = audit
        self.ttl = ttl
        self.ttlText = ttlText
        self.lockDirectory = lockDirectory ?? MetaCache.defaultDirectory()
            .deletingLastPathComponent()
            .appendingPathComponent("locks")
    }

    public func run(_ arguments: [String]) throws -> Int32 {
        let call = ProxyClassifier.classify(arguments)

        switch call.kind {
        case .passthrough:
            // Recorded too, although nothing is cached: `op run`, `op inject`
            // and `--otp` reach real secrets, and a log that shows only the
            // cacheable calls cannot answer "what asked for a credential".
            let status = try onePassword.passthrough(arguments)
            record(call, hit: false)
            return status

        case .mutating:
            let status = try onePassword.passthrough(arguments)
            record(call, hit: false)
            // A create or edit can make any cached listing wrong, so the
            // metadata cache is dropped rather than aged out. This is what
            // lets it live without an expiry. Prefetched items go with it:
            // they answer far more call shapes than a listing does, so a
            // stale one is correspondingly worse.
            if status == 0 {
                meta.clear()
                items.clear()
                // The digest cache holds the same values under a different key
                // and is consulted first; left alone it would answer
                // `op read` with the pre-edit value for the rest of its TTL.
                try? keychain.clear(profile: Self.profileName)
                // The prefetch is gone now, and every call until it is rebuilt
                // prompts. Ask the warm-up agent to rebuild it right away: the
                // person who just edited 1Password is at the keyboard, which
                // is the one moment an approval dialog costs nothing.
                Self.requestWarmUp()
            }
            return status

        case .metadata:
            return try serve(call, arguments: arguments, from: metadataLoader, store: storeMetadata)

        case .secret:
            return try serve(
                call,
                arguments: arguments,
                from: secretLoader,
                store: storeSecret,
                prefetched: { resolver.answer(for: arguments) }
            )
        }
    }

    // MARK: - Cache plumbing

    private typealias Loader = (String) -> String?
    private typealias Store = (String, String) -> Void

    private func serve(
        _ call: ClassifiedCall,
        arguments: [String],
        from load: Loader,
        store: Store,
        prefetched: (() -> String?)? = nil
    ) throws -> Int32 {
        guard let key = call.key else { return try onePassword.passthrough(arguments) }

        if let cached = load(key) {
            write(cached, to: FileHandle.standardOutput)
            record(call, hit: true)
            return 0
        }

        // The digest cache only matches a call spelled exactly as before. A
        // prefetched item is keyed by where it lives, so it answers the same
        // secret however it was addressed - including the first time.
        if let answer = prefetched?() {
            write(answer, to: FileHandle.standardOutput)
            record(call, hit: true, kind: "item-store")
            return 0
        }

        // Parallel sessions routinely ask for the same secret within the same
        // second. Without this, each one prompts. The holder fetches; the rest
        // wait and then find the value already cached.
        let lock = FileLock(directory: lockDirectory, name: key)
        lock.acquire()
        defer { lock.release() }

        if let cached = load(key) {
            write(cached, to: FileHandle.standardOutput)
            record(call, hit: true)
            return 0
        }

        let result = try onePassword.capture(arguments)
        write(result.standardOutput, to: FileHandle.standardOutput)
        write(result.standardError, to: FileHandle.standardError)

        if result.status == 0, !result.standardOutput.isEmpty {
            store(key, result.standardOutput)
        } else if result.status != 0, MetaCache.indicatesStaleLookup(result.standardError) {
            // The item exists somewhere but not where a cached listing said.
            // Dropping the listing makes the next lookup see current state.
            meta.clear()
        }

        record(call, hit: false)
        return result.status
    }

    private var metadataLoader: Loader {
        { key in meta.get(key: key) }
    }

    private func storeMetadata(key: String, value: String) {
        try? meta.put(key: key, value: value)
    }

    private var secretLoader: Loader {
        { key in
            guard let cached = try? keychain.get(name: key, profile: Self.profileName),
                  cached.isValid(reference: key, account: Self.profileName) else { return nil }
            return cached.value
        }
    }

    /// Whether a result may be stored at all. Two shapes are refused: a JSON
    /// document with an OTP field (it carries the seed, which must never sit
    /// in a cache, and a code that is wrong within 30 seconds), and a bare
    /// six-to-eight-digit line, which is what `--fields <otp-field>` returns
    /// and cannot be told apart from a PIN by name alone.
    static func isCacheable(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // Any JSON shape that carries an OTP field: the full item, a single
        // field object, or a `--fields` array.
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") {
            if trimmed.range(of: #""type"\s*:\s*"OTP""#, options: [.regularExpression, .caseInsensitive]) != nil {
                return false
            }
        }
        // Everything else is looked at token by token - a line of the table
        // format, a column of a `--fields` CSV line, a word of a seed shown in
        // groups of four - because op prints an OTP field as the code, the
        // seed, or an otpauth URI depending on the call. Refused: a
        // six-to-eight-digit code, an otpauth URI, a base32 run of 16 or
        // more characters (case-insensitive: a seed typed by hand keeps its
        // case). A base32-looking API key is refused too; that costs one
        // approval, never a wrong value.
        let tokens = trimmed.split(whereSeparator: { $0 == "," || $0.isNewline || $0 == "\t" })
        for token in tokens {
            let piece = token.trimmingCharacters(in: .whitespaces)
            // The table format puts the label first: "one-time password  otpauth://…".
            if piece.lowercased().contains("otpauth://") { return false }
            // The `ID:` line of the table format is the one place op prints a
            // bare lower-case base32 run that is not a seed: the item's ID, 26
            // characters. Only that line is exempt from the seed check below.
            if piece.hasPrefix("ID:") { continue }
            let words = piece.split(separator: " ").map(String.init)
            for word in words where word.count >= 6 && word.count <= 8 && word.allSatisfy(\.isNumber) {
                return false
            }
            // A seed as one word, or shown in groups of four - either way the
            // run without spaces is what is measured. A table line is looked
            // at word by word as well, so the label in front does not hide it.
            for candidate in [piece.replacingOccurrences(of: " ", with: "")] + words
            where candidate.count >= 16 {
                if candidate.range(of: "^[A-Z2-7]+=*$", options: .regularExpression) != nil { return false }
                // Lower-case base32 collides with an all-letter passphrase,
                // which is common and must stay cacheable; a seed almost
                // always carries digits, so lower case is refused only with
                // at least two of them. Item IDs are the other collision and
                // are handled by the `ID:` exemption above; in JSON they sit
                // in quotes and never form a bare run.
                if candidate.range(of: "^[a-z2-7]+=*$", options: .regularExpression) != nil,
                   candidate.filter(\.isNumber).count >= 2 {
                    return false
                }
            }
        }
        return true
    }

    private func storeSecret(key: String, value: String) {
        guard value.utf8.count <= Self.maximumSecretBytes, Self.isCacheable(value) else { return }
        let now = Date()
        let cached = CachedSecret(
            reference: key,
            account: Self.profileName,
            value: value,
            fetchedAt: now,
            expiresAt: now.addingTimeInterval(ttl)
        )
        try? keychain.put(cached, name: key, profile: Self.profileName)
    }

    /// Kicks the `dev.peter.op-cache.warm` LaunchAgent if it is installed.
    /// Best effort and silent: a machine without the agent just prompts on the
    /// next call, as it did before.
    static func requestWarmUp() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart", "gui/\(getuid())/dev.peter.op-cache.warm"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    // MARK: - Output and audit

    /// Byte-exact, so `--no-newline` and trailing whitespace survive the cache.
    private func write(_ text: String, to handle: FileHandle) {
        guard !text.isEmpty else { return }
        handle.write(Data(text.utf8))
    }

    /// The subject is the `op://` reference or item name the caller spelled -
    /// never a field value. Without it the log counts approvals but cannot say
    /// which secret was asked for, which is what a watcher needs to tell a
    /// routine fetch from a first-time one.
    private func record(_ call: ClassifiedCall, hit: Bool, kind: String? = nil) {
        let secrets = call.subject.map { [AuditSecret(name: call.subcommand, reference: $0)] } ?? []
        audit.record(
            AuditEvent(
                event: .proxy,
                profile: Self.profileName,
                account: "",
                secrets: secrets,
                ttl: call.kind == .secret ? ttlText : nil,
                subcommand: call.subcommand,
                cacheKind: kind ?? call.kind.rawValue,
                cacheHit: hit
            )
        )
    }
}

/// Advisory lock around a single cache key, so concurrent sessions asking for
/// the same secret produce one approval instead of one each.
struct FileLock {
    private let url: URL
    private var descriptor: Int32 = -1

    init(directory: URL, name: String) {
        url = directory.appendingPathComponent("\(name).lock")
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    func acquire() {
        let fd = open(url.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return }
        // Best effort: a failed lock costs an extra approval, never correctness.
        _ = flock(fd, LOCK_EX)
        Self.descriptors.withLock { $0[url.path] = fd }
    }

    func release() {
        guard let fd = Self.descriptors.withLock({ $0.removeValue(forKey: url.path) }) else { return }
        _ = flock(fd, LOCK_UN)
        close(fd)
    }

    private static let descriptors = Mutex<[String: Int32]>([:])
}

/// Minimal mutex so the lock survives the struct's value semantics.
final class Mutex<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) { self.value = value }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}
