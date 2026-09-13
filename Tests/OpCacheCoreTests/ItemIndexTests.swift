import Foundation
import Testing
@testable import OpCacheCore

private func makeIndex() -> ItemIndex {
    ItemIndex(
        builtAt: Date(timeIntervalSince1970: 0),
        accounts: [
            IndexedAccount(
                url: "everlastconsultinggmbh.1password.eu",
                aliases: ["everlastconsultinggmbh.1password.eu", "everlastconsultinggmbh", "shared@example.com"],
                vaults: [
                    IndexedVault(id: "v-emp", name: "Employee", items: [
                        IndexedItem(id: "i-pat", title: "supabase-everlast-pat"),
                    ]),
                    IndexedVault(id: "v-api", name: "API-Keys", items: [
                        IndexedItem(id: "i-n8n", title: "n8n-demo api"),
                        IndexedItem(id: "i-dup", title: "twin"),
                        IndexedItem(id: "i-dup2", title: "twin"),
                    ]),
                ]
            ),
            IndexedAccount(
                url: "strategie-fm.1password.eu",
                aliases: ["strategie-fm.1password.eu", "strategie-fm", "shared@example.com"],
                vaults: [
                    IndexedVault(id: "v-emp-fm", name: "Employee", items: [
                        IndexedItem(id: "i-ninox", title: "ninox"),
                    ]),
                ]
            ),
        ]
    )
}

@Test func resolvesByTitleAndIDIgnoringCase() throws {
    let index = makeIndex()
    let byTitle = try #require(SecretReference.parse("op://API-Keys/n8n-demo api/credential"))
    #expect(index.resolve(byTitle, accountHint: nil)
        == [ItemCoordinate(account: "everlastconsultinggmbh.1password.eu", vaultID: "v-api", itemID: "i-n8n")])

    // Measured against op: vault, item, and field lookups are case-insensitive.
    let mixedCase = try #require(SecretReference.parse("op://api-keys/N8N-DEMO API/credential"))
    #expect(index.resolve(mixedCase, accountHint: nil).count == 1)

    let byID = try #require(SecretReference.parse("op://v-api/i-n8n/credential"))
    #expect(index.resolve(byID, accountHint: nil).count == 1)
}

@Test func leavesAmbiguityToOp() throws {
    let index = makeIndex()
    // Same vault name in two accounts, different items: without a hint this is
    // one match per account, which the caller must not pick between.
    let shared = try #require(SecretReference.parse("op://Employee/ninox/credential"))
    #expect(index.resolve(shared, accountHint: nil).count == 1)
    #expect(index.resolve(shared, accountHint: "everlastconsultinggmbh").isEmpty)

    // Two items with the same title in one vault: op itself fails here.
    let twins = try #require(SecretReference.parse("op://API-Keys/twin/credential"))
    #expect(index.resolve(twins, accountHint: nil).count == 2)

    // An alias both accounts answer to narrows nothing.
    let pat = try #require(SecretReference.parse("op://Employee/supabase-everlast-pat/credential"))
    #expect(index.resolve(pat, accountHint: "shared@example.com").count == 1)
    #expect(index.resolve(pat, accountHint: "nonexistent-account").isEmpty)
}

@Test func resolvesItemGetAddressing() {
    let index = makeIndex()
    #expect(index.resolveItem("n8n-demo api", vaultHint: nil, accountHint: nil).count == 1)
    #expect(index.resolveItem("n8n-demo api", vaultHint: "API-Keys", accountHint: nil).count == 1)
    #expect(index.resolveItem("n8n-demo api", vaultHint: "Employee", accountHint: nil).isEmpty)
    #expect(index.resolveItem("i-n8n", vaultHint: "v-api", accountHint: "everlastconsultinggmbh").count == 1)
}

@Test func roundTripsThroughDiskWithPrivatePermissions() throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("op-cache-index-test-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: url) }

    try makeIndex().save(to: url)
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    let permissions = try #require(attributes[.posixPermissions] as? NSNumber)
    #expect(permissions.uint16Value & 0o077 == 0)

    let loaded = try #require(ItemIndex.load(from: url))
    #expect(loaded == makeIndex())
    #expect(loaded.itemCount == 5)

    // A world-readable index is treated as absent rather than trusted.
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    #expect(ItemIndex.load(from: url) == nil)
}

@Test func treatsURLMatchesAsCandidatesSoAmbiguityIsSeen() {
    // The real case: "telnyx.com" is both an item title and another item's
    // URL, so `op` reports "More than one item matches". A title-only index
    // saw one match and answered where op errors out.
    let index = ItemIndex(
        builtAt: Date(timeIntervalSince1970: 0),
        accounts: [IndexedAccount(url: "a.1password.eu", aliases: ["a"], vaults: [
            IndexedVault(id: "v", name: "Kunden-Zugaenge", items: [
                IndexedItem(id: "i-plain", title: "telnyx.com"),
                IndexedItem(id: "i-named", title: "Daniel Preisinger I telnyx.com",
                            urls: ["https://telnyx.com", "portal.telnyx.com"]),
            ]),
        ])]
    )
    #expect(index.resolveItem("telnyx.com", vaultHint: nil, accountHint: nil).count == 2)
    // The full href resolves the same way.
    #expect(index.resolveItem("https://telnyx.com", vaultHint: nil, accountHint: nil).count == 1)
    // A fragment of a URL is not a match for op, and need not be for us.
    #expect(index.resolveItem("portal.telnyx", vaultHint: nil, accountHint: nil).isEmpty)
    // An unrelated item stays unambiguous.
    #expect(index.resolveItem("Daniel Preisinger I telnyx.com", vaultHint: nil, accountHint: nil).count == 1)
}

@Test func discardsAnIndexWrittenBeforeURLsExisted() throws {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("op-cache-index-v1-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: url) }
    try #"{"version":1,"builtAt":"1970-01-01T00:00:00Z","accounts":[]}"#.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    #expect(ItemIndex.load(from: url) == nil)
}

@Test func aNarrowedPrefetchKeepsTheOtherAccountsInTheIndex() {
    // Tenth adversarial round: a one-account retry used to replace the index.
    let first = IndexedAccount(url: "first.1password.eu", aliases: ["first"], vaults: [])
    let second = IndexedAccount(url: "second.1password.eu", aliases: ["second"], vaults: [])
    let full = ItemIndex(builtAt: Date(), accounts: [first, second])
    let refreshed = IndexedAccount(url: "second.1password.eu", aliases: ["second", "neu"], vaults: [])

    let merged = ItemIndex.merging(existing: full, fresh: [refreshed])
    #expect(merged.accounts.map(\.url).sorted() == ["first.1password.eu", "second.1password.eu"])
    #expect(merged.accounts.first { $0.url == "second.1password.eu" }?.aliases == ["second", "neu"])
    // No previous index: the fresh accounts alone.
    #expect(ItemIndex.merging(existing: nil, fresh: [first]).accounts.count == 1)
}
