import Foundation

/// Where one item lives: which account, which vault, which item.
public struct ItemCoordinate: Codable, Sendable, Equatable, Hashable {
    /// The account URL, which is what the prefetch passes to `op --account`.
    public let account: String
    public let vaultID: String
    public let itemID: String

    public init(account: String, vaultID: String, itemID: String) {
        self.account = account
        self.vaultID = vaultID
        self.itemID = itemID
    }
}

public struct IndexedItem: Codable, Sendable, Equatable {
    public let id: String
    public let title: String
    /// Every `href` on the item.
    ///
    /// `op` resolves an item by its URLs as well as its title. Measured: the
    /// name "telnyx.com" matches both the item of that name and a second one
    /// titled "Daniel Preisinger I telnyx.com", because the latter carries
    /// https://telnyx.com as a URL - so `op` reports "More than one item
    /// matches" where a title-only index sees exactly one. Without the URLs
    /// the cache answers a call that `op` refuses.
    public var urls: [String]

    public init(id: String, title: String, urls: [String] = []) {
        self.id = id
        self.title = title
        self.urls = urls
    }

    private enum CodingKeys: String, CodingKey {
        case id, title, urls
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        urls = try container.decodeIfPresent([String].self, forKey: .urls) ?? []
    }
}

public struct IndexedVault: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public var items: [IndexedItem]

    public init(id: String, name: String, items: [IndexedItem]) {
        self.id = id
        self.name = name
        self.items = items
    }
}

public struct IndexedAccount: Codable, Sendable, Equatable {
    /// Canonical account URL, e.g. "everlastconsultinggmbh.1password.eu".
    public let url: String
    /// Everything `op --account` accepts for this account: URL, its leading
    /// label, e-mail, shorthand, and both UUIDs. An alias shared with another
    /// account (the same e-mail on two accounts here) simply makes a lookup
    /// ambiguous, which sends the call to `op`.
    public let aliases: [String]
    public var vaults: [IndexedVault]

    public init(url: String, aliases: [String], vaults: [IndexedVault]) {
        self.url = url
        self.aliases = aliases
        self.vaults = vaults
    }
}

/// On-disk map from names to IDs, written by the prefetch.
///
/// Everlast fork only. Holds titles, IDs, and vault names — the same class of
/// data as the metadata cache, never a field value. It lives beside that cache
/// with the same ownership and permission checks.
public struct ItemIndex: Codable, Sendable, Equatable {
    /// Raised to 2 when URLs joined the index: an index without them cannot
    /// spot the ambiguities `op` reports, so an old file is discarded rather
    /// than trusted.
    public static let currentVersion = 2

    public var version: Int
    public var builtAt: Date
    public var accounts: [IndexedAccount]

    public init(version: Int = ItemIndex.currentVersion, builtAt: Date, accounts: [IndexedAccount]) {
        self.version = version
        self.builtAt = builtAt
        self.accounts = accounts
    }

    /// The index after a prefetch of `fresh`: those accounts replace their
    /// previous entries, every other account is kept. A run narrowed with
    /// `--account` must not drop the rest of the index, or their items become
    /// unreachable by reference while still sitting in the Keychain.
    /// Measured on 13.09.2026: after a one-account retry the index listed
    /// "1 account(s)" and the other account's 982 items missed the cache.
    public static func merging(existing: ItemIndex?, fresh: [IndexedAccount]) -> ItemIndex {
        let retained = (existing?.accounts ?? []).filter { old in
            !fresh.contains { $0.url == old.url }
        }
        return ItemIndex(builtAt: Date(), accounts: fresh + retained)
    }

    // MARK: - Resolution

    /// Every item matching a reference, optionally narrowed by `--account`.
    ///
    /// Ambiguity is deliberately not resolved here. Two items with the same
    /// title in the same vault make `op` itself fail with "more than one item
    /// matches"; guessing one would turn that error into a wrong answer.
    /// Callers require exactly one match and fall through to `op` otherwise.
    public func resolve(_ reference: SecretReference, accountHint: String?) -> [ItemCoordinate] {
        var matches: [ItemCoordinate] = []
        for account in accounts where account.matches(accountHint) {
            for vault in account.vaults where vault.matches(reference.vault) {
                for item in vault.items where item.matches(reference.item) {
                    matches.append(
                        ItemCoordinate(account: account.url, vaultID: vault.id, itemID: item.id)
                    )
                }
            }
        }
        return dedupe(matches)
    }

    /// Items addressed the way `op item get` does it: a title or ID, with the
    /// vault as a separate optional argument rather than part of a reference.
    public func resolveItem(_ needle: String, vaultHint: String?, accountHint: String?) -> [ItemCoordinate] {
        var matches: [ItemCoordinate] = []
        for account in accounts where account.matches(accountHint) {
            for vault in account.vaults {
                if let vaultHint, !vault.matches(vaultHint) { continue }
                for item in vault.items where item.matches(needle) {
                    matches.append(
                        ItemCoordinate(account: account.url, vaultID: vault.id, itemID: item.id)
                    )
                }
            }
        }
        return dedupe(matches)
    }

    /// The same item reachable through two aliases of one account is one
    /// match, not two.
    private func dedupe(_ matches: [ItemCoordinate]) -> [ItemCoordinate] {
        var seen = Set<ItemCoordinate>()
        return matches.filter { seen.insert($0).inserted }
    }

    // MARK: - Storage

    public static func defaultURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Caches/op-cache/index.json")
    }

    /// Returns nil rather than throwing: a missing or unreadable index must
    /// cost an approval, never a broken `op`.
    public static func load(from url: URL? = nil) -> ItemIndex? {
        let indexURL = url ?? defaultURL()
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: indexURL.path) else {
            return nil
        }
        if let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value != getuid() {
            return nil
        }
        if let permissions = attributes[.posixPermissions] as? NSNumber,
           permissions.uint16Value & 0o077 != 0 {
            return nil
        }
        guard let data = try? Data(contentsOf: indexURL) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let index = try? decoder.decode(ItemIndex.self, from: data),
              index.version == ItemIndex.currentVersion else { return nil }
        return index
    }

    public func save(to url: URL? = nil) throws {
        let indexURL = url ?? Self.defaultURL()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(self)

        try FileManager.default.createDirectory(
            at: indexURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try data.write(to: indexURL, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: indexURL.path
        )
    }

    @discardableResult
    public static func remove(at url: URL? = nil) -> Bool {
        let indexURL = url ?? defaultURL()
        return (try? FileManager.default.removeItem(at: indexURL)) != nil
    }

    public var itemCount: Int {
        accounts.reduce(0) { $0 + $1.vaults.reduce(0) { $0 + $1.items.count } }
    }
}

extension IndexedAccount {
    /// No hint means every account is a candidate, which is exactly how `op`
    /// behaves: it searches the account it would default to, and a name that
    /// exists in two accounts is ambiguous either way.
    func matches(_ hint: String?) -> Bool {
        guard let hint, !hint.isEmpty else { return true }
        return aliases.contains { $0.caseInsensitiveCompare(hint) == .orderedSame }
    }
}

extension IndexedVault {
    func matches(_ needle: String) -> Bool {
        id.caseInsensitiveCompare(needle) == .orderedSame
            || name.caseInsensitiveCompare(needle) == .orderedSame
    }
}

extension IndexedItem {
    /// Deliberately wider than `op`: a needle that matches a URL with or
    /// without its scheme counts as a candidate. Being too generous costs a
    /// passthrough and an approval; being too narrow hands back a value where
    /// `op` reports an ambiguity.
    func matches(_ needle: String) -> Bool {
        if id.caseInsensitiveCompare(needle) == .orderedSame { return true }
        if title.caseInsensitiveCompare(needle) == .orderedSame { return true }
        return urls.contains { url in
            Self.urlForms(of: url).contains { $0.caseInsensitiveCompare(needle) == .orderedSame }
        }
    }

    static func urlForms(of url: String) -> [String] {
        var forms = [url]
        for scheme in ["https://", "http://"] where url.lowercased().hasPrefix(scheme) {
            let bare = String(url.dropFirst(scheme.count))
            forms.append(bare)
            if bare.lowercased().hasPrefix("www.") { forms.append(String(bare.dropFirst(4))) }
        }
        if url.lowercased().hasPrefix("www.") { forms.append(String(url.dropFirst(4))) }
        return forms
    }
}
