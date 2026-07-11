import Foundation
import Testing
@testable import OpCacheCore

// Serialized: the real Keychain is shared state, and concurrent enumeration
// while another test mutates items returns unstable results.
@Suite(.serialized)
struct KeychainStoreTests {
    @Test func keychainRoundTripAndClear() throws {
        let profile = "test-\(UUID().uuidString)"
        let name = "DUMMY_TOKEN"
        let store = KeychainStore()
        let now = Date()
        let secret = CachedSecret(
            reference: "op://test/item/field",
            account: "my.1password.eu",
            value: "not-a-real-secret",
            fetchedAt: now,
            expiresAt: now.addingTimeInterval(60)
        )
        defer { try? store.clear(profile: profile) }

        #expect(try store.get(name: name, profile: profile) == nil)
        try store.put(secret, name: name, profile: profile)
        let maybeLoaded = try store.get(name: name, profile: profile)
        let loaded = try #require(maybeLoaded)
        #expect(loaded.value == "not-a-real-secret")
        #expect(loaded.reference == secret.reference)
        #expect(loaded.account == secret.account)

        try store.clear(profile: profile)
        #expect(try store.get(name: name, profile: profile) == nil)
    }

    @Test func keychainListsOnlyEntriesOfTheProfile() throws {
        let profile = "test-\(UUID().uuidString)"
        let otherProfile = "test-\(UUID().uuidString)"
        let store = KeychainStore()
        let now = Date()
        let secret = CachedSecret(
            reference: "op://test/item/field",
            account: "my.1password.eu",
            value: "not-a-real-secret",
            fetchedAt: now,
            expiresAt: now.addingTimeInterval(60)
        )
        defer {
            try? store.clear(profile: profile)
            try? store.clear(profile: otherProfile)
        }

        #expect(try store.list(profile: profile) == [])

        try store.put(secret, name: "A_TOKEN", profile: profile)
        try store.put(secret, name: "B_TOKEN", profile: profile)
        try store.put(secret, name: "OTHER_TOKEN", profile: otherProfile)

        #expect(try store.list(profile: profile).sorted() == ["A_TOKEN", "B_TOKEN"])
        #expect(try store.list(profile: otherProfile) == ["OTHER_TOKEN"])

        let allProfiles = try store.allProfiles()
        #expect(allProfiles.contains(profile))
        #expect(allProfiles.contains(otherProfile))

        try store.clear(profile: profile)
        #expect(try store.list(profile: profile) == [])
        #expect(try store.list(profile: otherProfile) == ["OTHER_TOKEN"])
    }
}
