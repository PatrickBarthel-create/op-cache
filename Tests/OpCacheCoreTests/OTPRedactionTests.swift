import Testing
@testable import OpCacheCore

private let withOTP = """
{"id":"i-1","title":"Butzemillen","fields":[
 {"id":"username","type":"STRING","label":"username","value":"user@example.com"},
 {"id":"password","type":"CONCEALED","label":"password","value":"pw"},
 {"id":"TOTP_x","type":"OTP","label":"one-time password","value":"JBSWY3DPEHPK3PXP","totp":"123456"}]}
"""

@Test func removesSeedAndCodeButKeepsTheField() throws {
    let redacted = try #require(OTPRedaction.redact(withOTP))
    // The seed is the thing that must never be stored.
    #expect(!redacted.contains("JBSWY3DPEHPK3PXP"))
    #expect(!redacted.contains("123456"))
    // The field stays so the resolver can still see its type and refuse.
    #expect(redacted.contains("TOTP_x"))
    #expect(redacted.contains("user@example.com"))

    let payload = try #require(ItemPayload.decode(redacted))
    #expect(OTPRedaction.containsOTPField(payload))
    #expect(payload.field(named: "username")?.value == "user@example.com")
}

@Test func leavesDocumentsWithoutOTPUntouched() throws {
    let plain = #"{"id":"i","title":"t","fields":[{"id":"a","type":"STRING","label":"a","value":"v"}]}"#
    // Byte-identical, because `--format json` replays it verbatim.
    #expect(OTPRedaction.redact(plain) == plain)
    #expect(OTPRedaction.redact("not json") == nil)
}

@Test func resolverRefusesEveryOTPPath() throws {
    let redacted = try #require(OTPRedaction.redact(withOTP))
    let index = ItemIndex(
        builtAt: .init(timeIntervalSince1970: 0),
        accounts: [IndexedAccount(url: "a.1password.eu", aliases: ["a.1password.eu", "a"],
            vaults: [IndexedVault(id: "v", name: "Vault", items: [IndexedItem(id: "i-1", title: "Butzemillen")])])]
    )
    let coordinate = ItemCoordinate(account: "a.1password.eu", vaultID: "v", itemID: "i-1")
    let resolver = ItemResolver(loadItem: { $0 == coordinate ? redacted : nil }, loadIndex: { index })

    // Fields that are not one-time passwords still come from cache.
    #expect(resolver.answer(for: ["read", "op://Vault/Butzemillen/username"]) == "user@example.com\n")
    // The OTP field itself never does, by reference or by --fields.
    #expect(resolver.answer(for: ["read", "op://Vault/Butzemillen/one-time password"]) == nil)
    #expect(resolver.answer(for: ["item", "get", "i-1", "--fields", "TOTP_x", "--reveal"]) == nil)
    #expect(resolver.answer(for: ["item", "get", "i-1", "--fields", "username,TOTP_x", "--reveal"]) == nil)
    // Nor does the full document, which would no longer match op's output.
    #expect(resolver.answer(for: ["item", "get", "i-1", "--format", "json"]) == nil)
}
