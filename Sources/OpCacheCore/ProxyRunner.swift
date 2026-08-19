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
            return try onePassword.passthrough(arguments)

        case .mutating:
            let status = try onePassword.passthrough(arguments)
            // A create or edit can make any cached listing wrong, so the
            // metadata cache is dropped rather than aged out. This is what
            // lets it live without an expiry. Prefetched items go with it:
            // they answer far more call shapes than a listing does, so a
            // stale one is correspondingly worse.
            if status == 0 {
                meta.clear()
                items.clear()
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

    private func storeSecret(key: String, value: String) {
        guard value.utf8.count <= Self.maximumSecretBytes else { return }
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

    // MARK: - Output and audit

    /// Byte-exact, so `--no-newline` and trailing whitespace survive the cache.
    private func write(_ text: String, to handle: FileHandle) {
        guard !text.isEmpty else { return }
        handle.write(Data(text.utf8))
    }

    private func record(_ call: ClassifiedCall, hit: Bool, kind: String? = nil) {
        audit.record(
            AuditEvent(
                event: .proxy,
                profile: Self.profileName,
                account: "",
                secrets: [],
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
