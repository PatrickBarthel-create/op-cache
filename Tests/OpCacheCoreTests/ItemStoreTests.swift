import Foundation
import Testing
@testable import OpCacheCore

@Test func bundlesRoundTripThroughJSON() throws {
    let bundle = VaultBundle(items: [
        "i-1": #"{"id":"i-1","title":"one","fields":[]}"#,
        "i-2": #"{"id":"i-2","title":"zwö \" mit Umlaut","fields":[]}"#,
    ])
    let decoded = try #require(VaultBundle.decode(bundle.encoded()))
    #expect(decoded == bundle)
    // The stored document must survive verbatim: `--format json` replays it
    // byte for byte rather than re-encoding it.
    #expect(decoded.items["i-2"] == #"{"id":"i-2","title":"zwö \" mit Umlaut","fields":[]}"#)
}

@Test func vaultKeysAreStableAndDistinct() {
    let a = ItemStore.key(account: "everlast.1password.eu", vaultID: "v1")
    let b = ItemStore.key(account: "everlast.1password.eu", vaultID: "v2")
    let c = ItemStore.key(account: "strategie.1password.eu", vaultID: "v1")
    #expect(a == ItemStore.key(account: "everlast.1password.eu", vaultID: "v1"))
    #expect(a != b)
    #expect(a != c)
    // Hashed: the key names neither the account nor the vault.
    #expect(!a.contains("everlast"))
    #expect(a.hasPrefix("v"))
    #expect(a.count == 65)
}

@Test func rejectsBundlesLargerThanTheLimit() {
    let store = ItemStore()
    let huge = VaultBundle(items: ["big": String(repeating: "x", count: ItemStore.maximumBundleBytes + 1)])
    #expect(throws: (any Error).self) {
        try store.put(huge, account: "test.invalid", vaultID: "v", expiresAt: Date())
    }
}

@Test func aClearLeavesAMarkAPrefetchCanSee() {
    // Twelfth adversarial round: a prefetch that started before a write must
    // not write pre-write documents back after the clear.
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let before = Date().addingTimeInterval(-1)
    #expect(!ItemStore.invalidated(since: before, in: directory))
    ItemStore.markInvalidated(in: directory)
    #expect(ItemStore.invalidated(since: before, in: directory))
    #expect(!ItemStore.invalidated(since: Date().addingTimeInterval(60), in: directory))
}
