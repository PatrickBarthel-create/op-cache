import CryptoKit
import Foundation

/// One prefetched vault: its items' verbatim `op item get --format json`
/// output, keyed by item ID.
///
/// Bundling exists because of how macOS grants Keychain access: per entry and
/// per program, never per session. A rebuilt op-cache is a different program
/// to the Keychain - measured, the CDHash changes on every build - so it is
/// asked to confirm each entry it did not write itself. At one entry per item
/// that meant 990 dialogs. At one per vault it is 16, and a fresh
/// `unlock --all` after an update avoids them entirely, because then the
/// running binary is the one that wrote them.
public struct VaultBundle: Codable, Sendable, Equatable {
    /// Item ID to the raw JSON document `op` produced for it.
    public var items: [String: String]

    public init(items: [String: String] = [:]) {
        self.items = items
    }

    public func encoded() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }

    public static func decode(_ text: String) -> VaultBundle? {
        guard let data = text.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(VaultBundle.self, from: data)
    }
}

/// Keychain store for prefetched vaults, keyed by where an item lives rather
/// than by how a caller spelled the request.
///
/// Everlast fork only, and the reason a prefetch is worth anything at all:
/// the proxy's own cache is keyed by a digest of the argument vector, so a
/// value fetched in advance could never be found by a differently spelled
/// call. Keying on (account, vault) makes one stored copy answer `op read`,
/// `op item get`, titles, IDs, and either spelling of `--account`.
///
/// What is stored is every field value of every item in clear text, held for
/// the configured TTL. This is the widest thing this tool does.
public struct ItemStore: Sendable {
    /// Separate Keychain profile so `op-cache clear _items` and the sweep can
    /// reach prefetched vaults without touching proxied call results.
    public static let profileName = "_items"

    /// Single items above this are skipped rather than truncated: the Keychain
    /// is a poor store for blobs, and a document-sized item is not a credential.
    public static let maximumItemBytes = 256 * 1024
    /// A whole vault's bundle. The largest vault here holds 299 items.
    public static let maximumBundleBytes = 16 * 1024 * 1024

    private let keychain: KeychainStore

    public init(keychain: KeychainStore = KeychainStore()) {
        self.keychain = keychain
    }

    /// Stable per-vault key. Hashed rather than concatenated so the Keychain
    /// account attribute stays a fixed length and names no vault.
    public static func key(account: String, vaultID: String) -> String {
        let joined = [account, vaultID].joined(separator: "\u{0}")
        let digest = SHA256.hash(data: Data(joined.utf8))
        return "v" + digest.map { String(format: "%02x", $0) }.joined()
    }

    public func get(_ coordinate: ItemCoordinate) -> String? {
        let key = Self.key(account: coordinate.account, vaultID: coordinate.vaultID)
        guard let cached = try? keychain.get(name: key, profile: Self.profileName),
              cached.isValid(reference: key, account: Self.profileName),
              let bundle = VaultBundle.decode(cached.value) else { return nil }
        return bundle.items[coordinate.itemID]
    }

    public func put(_ bundle: VaultBundle, account: String, vaultID: String, expiresAt: Date) throws {
        let encoded = try bundle.encoded()
        guard encoded.utf8.count <= Self.maximumBundleBytes else {
            throw OpCacheError.message("Vault bundle exceeds \(Self.maximumBundleBytes) bytes.")
        }
        let key = Self.key(account: account, vaultID: vaultID)
        try keychain.put(
            CachedSecret(
                reference: key,
                account: Self.profileName,
                value: encoded,
                fetchedAt: Date(),
                expiresAt: expiresAt
            ),
            name: key,
            profile: Self.profileName
        )
    }

    /// Drops every prefetched vault and the index that names them.
    ///
    /// Called after any mutating `op` call succeeds, for the same reason the
    /// metadata cache is dropped there: an edited item would otherwise be
    /// served from the prefetch until its TTL ran out, and this store answers
    /// far more call shapes than the metadata cache does.
    @discardableResult
    public func clear() -> Int {
        let names = (try? keychain.list(profile: Self.profileName)) ?? []
        for name in names {
            try? keychain.delete(name: name, profile: Self.profileName)
        }
        ItemIndex.remove()
        Self.markInvalidated()
        return names.count
    }

    /// Where a clear leaves its timestamp. A prefetch that started before it
    /// holds pre-clear documents in memory and must not write them back.
    public static func invalidationMarkURL(in directory: URL? = nil) -> URL {
        (directory ?? MetaCache.defaultDirectory().deletingLastPathComponent())
            .appendingPathComponent("invalidated")
    }

    public static func markInvalidated(in directory: URL? = nil) {
        let url = invalidationMarkURL(in: directory)
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try? Data().write(to: url)
        try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: url.path)
    }

    /// Whether a clear happened after `moment`.
    public static func invalidated(since moment: Date, in directory: URL? = nil) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: invalidationMarkURL(in: directory).path),
              let modified = attributes[.modificationDate] as? Date else { return false }
        return modified > moment
    }

    /// Live and expired bundle counts, for `op-cache status`.
    public func counts() -> (live: Int, expired: Int, latestExpiry: Date?) {
        let names = (try? keychain.list(profile: Self.profileName)) ?? []
        var live = 0
        var expired = 0
        var latest: Date?
        for name in names {
            guard let cached = try? keychain.get(name: name, profile: Self.profileName),
                  cached.isValid(reference: name, account: Self.profileName) else {
                expired += 1
                continue
            }
            live += 1
            if latest == nil || cached.expiresAt > latest! { latest = cached.expiresAt }
        }
        return (live, expired, latest)
    }
}
