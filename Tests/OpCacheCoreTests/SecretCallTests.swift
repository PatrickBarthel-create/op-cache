import Testing
@testable import OpCacheCore

@Test func parsesReadCalls() {
    #expect(
        SecretCall.parse(["read", "op://Employee/token/credential"])
            == .read(
                reference: SecretReference(vault: "Employee", item: "token", field: "credential"),
                account: nil,
                noNewline: false
            )
    )
    #expect(
        SecretCall.parse(["read", "--account", "everlast", "--no-newline", "op://Employee/token/credential"])
            == .read(
                reference: SecretReference(vault: "Employee", item: "token", field: "credential"),
                account: "everlast",
                noNewline: true
            )
    )
    #expect(
        SecretCall.parse(["read", "--account=everlast", "op://Employee/token/credential"])?.account
            == "everlast"
    )
}

@Test func refusesReadShapesWithSideEffectsOrUnknownFlags() {
    // Writes a file; its stdout is not the value.
    #expect(SecretCall.parse(["read", "--out-file", "/tmp/x", "op://Employee/token/credential"]) == nil)
    #expect(SecretCall.parse(["read", "--unknown", "op://Employee/token/credential"]) == nil)
    #expect(SecretCall.parse(["read"]) == nil)
    #expect(SecretCall.parse(["read", "op://Employee/token", "op://Employee/other/x"]) == nil)
}

@Test func parsesItemGetJSONAndFields() {
    #expect(
        SecretCall.parse(["item", "get", "token", "--vault", "Employee", "--format", "json"])
            == .itemJSON(item: "token", vault: "Employee", account: nil)
    )
    #expect(
        SecretCall.parse(["item", "get", "token", "--fields", "credential,username", "--reveal"])
            == .itemFields(
                item: "token", vault: nil, account: nil,
                specs: ["credential", "username"], reveal: true
            )
    )
}

@Test func refusesItemGetShapesThatCannotBeReproduced() {
    // Default output prints relative timestamps ("1 month ago").
    #expect(SecretCall.parse(["item", "get", "token"]) == nil)
    // Time-based, and wrong within 30 seconds.
    #expect(SecretCall.parse(["item", "get", "token", "--otp"]) == nil)
    // Measured at 0.2% of calls and its own output shape.
    #expect(SecretCall.parse(["item", "get", "token", "--fields", "credential", "--format", "json"]) == nil)
    #expect(SecretCall.parse(["item", "get", "token", "--format", "yaml"]) == nil)
    #expect(SecretCall.parse(["item", "get", "op://Employee/token", "--format", "json"]) == nil)
    #expect(SecretCall.parse(["item", "list", "--format", "json"]) == nil)
    #expect(SecretCall.parse(["vault", "list"]) == nil)
}
