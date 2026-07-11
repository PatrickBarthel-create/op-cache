import Foundation
import Testing
@testable import OpCacheCore

@Test func cachedSecretRequiresMatchingReferenceAccountAndFreshExpiry() {
    let now = Date(timeIntervalSince1970: 1_000)
    let cached = CachedSecret(
        reference: "op://vault/item/field",
        account: "my.1password.eu",
        value: "secret",
        fetchedAt: now,
        expiresAt: now.addingTimeInterval(60)
    )

    #expect(cached.isValid(reference: "op://vault/item/field", account: "my.1password.eu", at: now))
    #expect(!cached.isValid(reference: "op://vault/other/field", account: "my.1password.eu", at: now))
    #expect(!cached.isValid(reference: "op://vault/item/field", account: "other.1password.eu", at: now))
    #expect(!cached.isValid(
        reference: "op://vault/item/field",
        account: "my.1password.eu",
        at: now.addingTimeInterval(60)
    ))
}

@Test func legacyCachedSecretWithoutAccountNeverValidates() throws {
    let json = """
    {"reference": "op://vault/item/field", "value": "secret", \
    "fetchedAt": 1000, "expiresAt": 4102444800}
    """
    let cached = try JSONDecoder().decode(CachedSecret.self, from: Data(json.utf8))
    #expect(!cached.isValid(reference: "op://vault/item/field", account: "my.1password.eu"))
}

@Test func profileValidationRejectsUnsafeNamesAndReferences() {
    let unsafeName = ProfileConfig(account: "my.1password.eu", secrets: ["BAD NAME": "op://v/i/f"])
    #expect(throws: (any Error).self) { try unsafeName.validate() }

    let unsafeReference = ProfileConfig(account: "my.1password.eu", secrets: ["TOKEN": "plaintext"])
    #expect(throws: (any Error).self) { try unsafeReference.validate() }
}
