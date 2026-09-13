import Foundation

public struct PrefetchSummary: Sendable {
    public var accounts: Int = 0
    public var vaults: Int = 0
    public var items: Int = 0
    public var stored: Int = 0
    public var skipped: Int = 0
    public var failed: Int = 0
    public var expiresAt: Date = Date()
}

/// Reads every item in every vault of every configured account and stores it.
///
/// Everlast fork only, and the widest thing this tool does. Upstream caches an
/// allowlist someone wrote down; this caches the account. What it buys is that
/// the first call for a secret costs no approval either — the measured working
/// set was never the problem, the first touch of each new secret was.
///
/// What it costs is stated plainly because it should be: for the duration of
/// the TTL, every field of every item is readable from the Keychain by any
/// process running as this user, without a prompt.
public struct PrefetchRunner: Sendable {
    /// Concurrent `op item get` calls. Measured on this machine: 1.10s per
    /// item sequentially against 0.18s at six workers, i.e. 18 minutes versus
    /// under three for the full account.
    public static let defaultWorkers = 6

    private let onePassword: OnePassword
    private let store: ItemStore
    private let audit: AuditLog

    public init(onePassword: OnePassword = OnePassword(), store: ItemStore = ItemStore(), audit: AuditLog) {
        self.onePassword = onePassword
        self.store = store
        self.audit = audit
    }

    public func run(
        accountFilter: [String]?,
        ttl: TimeInterval,
        ttlText: String,
        workers: Int = PrefetchRunner.defaultWorkers,
        log: @escaping @Sendable (String) -> Void
    ) throws -> PrefetchSummary {
        var summary = PrefetchSummary()
        let expiresAt = Date().addingTimeInterval(ttl)
        summary.expiresAt = expiresAt

        let accounts = try listAccounts().filter { account in
            guard let accountFilter, !accountFilter.isEmpty else { return true }
            return accountFilter.contains { candidate in
                account.aliases.contains { $0.caseInsensitiveCompare(candidate) == .orderedSame }
            }
        }
        guard !accounts.isEmpty else {
            throw OpCacheError.message("No matching 1Password accounts. Check 'op account list'.")
        }

        var indexed: [IndexedAccount] = []

        for account in accounts {
            log("Authenticate 1Password for \(account.url).")
            do {
                try onePassword.authenticate(account: account.url)
            } catch {
                // An account this machine can reach but not sign into (a
                // customer tenant that revoked access) must not abort the run.
                log("  skipped \(account.url): \(error.localizedDescription)")
                continue
            }

            let vaults = (try? listVaults(account: account.url)) ?? []
            if vaults.isEmpty {
                log("  \(account.url): no vaults visible, skipping")
                continue
            }
            summary.accounts += 1

            var indexedVaults: [IndexedVault] = []
            for vault in vaults {
                let items = (try? listItems(account: account.url, vault: vault.id)) ?? []
                summary.vaults += 1
                summary.items += items.count
                log("  \(vault.name): \(items.count) item(s)")

                let result = fetch(
                    items: items,
                    account: account.url,
                    vaultID: vault.id,
                    workers: max(1, workers)
                )
                summary.stored += result.bundle.items.count
                summary.skipped += result.skipped
                summary.failed += result.failed

                // One Keychain entry per vault, written once the whole vault
                // is in hand: see VaultBundle for why the granularity matters.
                if !result.bundle.items.isEmpty {
                    do {
                        try store.put(
                            result.bundle,
                            account: account.url,
                            vaultID: vault.id,
                            expiresAt: expiresAt
                        )
                    } catch {
                        log("  \(vault.name): not stored (\(error.localizedDescription))")
                        summary.stored -= result.bundle.items.count
                        summary.failed += result.bundle.items.count
                    }
                }
                // URLs come from the fetched documents rather than the
                // listing, so the index knows exactly what `op` would match.
                let enriched = items.map { item -> IndexedItem in
                    guard let document = result.bundle.items[item.id],
                          let payload = ItemPayload.decode(document) else { return item }
                    return IndexedItem(id: item.id, title: item.title, urls: payload.urls)
                }
                indexedVaults.append(IndexedVault(id: vault.id, name: vault.name, items: enriched))
            }

            indexed.append(
                IndexedAccount(url: account.url, aliases: account.aliases, vaults: indexedVaults)
            )
        }

        // Merge, do not replace: a run narrowed with `--account` (the warm-up
        // agent retries only the account that skipped) must not drop the other
        // accounts from the index, or their prefetched items become
        // unreachable by reference while still sitting in the Keychain -
        // measured on 13.09.2026: after a one-account retry the index listed
        // "1 account(s)" and the other 982 items missed the cache.
        try ItemIndex.merging(existing: ItemIndex.load(), fresh: indexed).save()

        audit.record(
            AuditEvent(
                event: .unlock,
                profile: ItemStore.profileName,
                account: indexed.map(\.url).joined(separator: ","),
                secrets: [],
                ttl: ttlText,
                expiresAt: expiresAt,
                subcommand: "prefetch",
                cacheKind: "item-store",
                cacheHit: false
            )
        )

        return summary
    }

    // MARK: - Fetching

    private func fetch(
        items: [IndexedItem],
        account: String,
        vaultID: String,
        workers: Int
    ) -> (bundle: VaultBundle, skipped: Int, failed: Int) {
        let collected = Mutex<VaultBundle>(VaultBundle())
        let counters = Mutex<(skipped: Int, failed: Int)>((0, 0))
        let cursor = Mutex<Int>(0)
        let group = DispatchGroup()

        for _ in 0..<workers {
            DispatchQueue.global().async(group: group) {
                while true {
                    let index = cursor.withLock { value -> Int in
                        let current = value
                        value += 1
                        return current
                    }
                    guard index < items.count else { return }
                    let item = items[index]
                    let arguments = [
                        "item", "get", item.id,
                        "--account", account,
                        "--vault", vaultID,
                        "--format", "json",
                    ]
                    guard let result = try? onePassword.capture(arguments),
                          result.status == 0,
                          !result.standardOutput.isEmpty else {
                        counters.withLock { $0.failed += 1 }
                        continue
                    }
                    guard result.standardOutput.utf8.count <= ItemStore.maximumItemBytes else {
                        counters.withLock { $0.skipped += 1 }
                        continue
                    }
                    // A one-time-password seed must never reach the cache; an
                    // item whose seed cannot be removed is not stored at all.
                    guard let document = OTPRedaction.redact(result.standardOutput) else {
                        counters.withLock { $0.skipped += 1 }
                        continue
                    }
                    collected.withLock { $0.items[item.id] = document }
                }
            }
        }

        group.wait()
        let tallies = counters.withLock { $0 }
        return (collected.withLock { $0 }, tallies.skipped, tallies.failed)
    }

    // MARK: - Listing

    struct AccountEntry: Sendable {
        let url: String
        let aliases: [String]
    }

    private struct AccountWire: Decodable {
        let url: String
        let email: String?
        let user_uuid: String?
        let account_uuid: String?
        let shorthand: String?
    }

    private struct VaultWire: Decodable {
        let id: String
        let name: String
    }

    private struct ItemWire: Decodable {
        let id: String
        let title: String
    }

    func listAccounts() throws -> [AccountEntry] {
        let result = try onePassword.capture(["account", "list", "--format", "json"])
        guard result.status == 0, let data = result.standardOutput.data(using: .utf8),
              let wire = try? JSONDecoder().decode([AccountWire].self, from: data) else {
            throw OpCacheError.message("Could not list 1Password accounts.")
        }
        return wire.map { entry in
            // `--account` takes any of these. The leading label of the URL is
            // what gets typed in practice ("everlastconsultinggmbh").
            var aliases = [entry.url]
            if let label = entry.url.split(separator: ".").first { aliases.append(String(label)) }
            aliases.append(contentsOf: [entry.email, entry.user_uuid, entry.account_uuid, entry.shorthand].compactMap { $0 })
            return AccountEntry(url: entry.url, aliases: aliases)
        }
    }

    private func listVaults(account: String) throws -> [IndexedVault] {
        let result = try onePassword.capture(["vault", "list", "--account", account, "--format", "json"])
        guard result.status == 0, let data = result.standardOutput.data(using: .utf8),
              let wire = try? JSONDecoder().decode([VaultWire].self, from: data) else { return [] }
        return wire.map { IndexedVault(id: $0.id, name: $0.name, items: []) }
    }

    private func listItems(account: String, vault: String) throws -> [IndexedItem] {
        let result = try onePassword.capture([
            "item", "list", "--account", account, "--vault", vault, "--format", "json",
        ])
        guard result.status == 0, let data = result.standardOutput.data(using: .utf8),
              let wire = try? JSONDecoder().decode([ItemWire].self, from: data) else { return [] }
        return wire.map { IndexedItem(id: $0.id, title: $0.title) }
    }
}
