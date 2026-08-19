import Testing
@testable import OpCacheCore

@Test func parsesThreeAndFourComponentReferences() {
    let plain = SecretReference.parse("op://Employee/token/credential")
    #expect(plain == SecretReference(vault: "Employee", item: "token", field: "credential"))
    #expect(plain?.fieldPath == "credential")

    let sectioned = SecretReference.parse("op://Employee/token/Server/password")
    #expect(sectioned?.section == "Server")
    #expect(sectioned?.fieldPath == "Server/password")
}

@Test func refusesReferencesItMustNotInterpret() {
    // A whole item, not a field.
    #expect(SecretReference.parse("op://Employee/token") == nil)
    // Deeper than 1Password defines.
    #expect(SecretReference.parse("op://Employee/token/a/b/c") == nil)
    #expect(SecretReference.parse("op://Employee//credential") == nil)
    #expect(SecretReference.parse("Employee/token/credential") == nil)
    #expect(SecretReference.parse("op://") == nil)
}

@Test func keepsSpacesAndPunctuationVerbatim() {
    let reference = SecretReference.parse("op://API-Keys/n8n-demo api/valid from")
    #expect(reference?.item == "n8n-demo api")
    #expect(reference?.field == "valid from")
}

@Test func refusesCharactersOpItselfRejects() {
    // Measured character by character against `op read`: these fail its own
    // reference parser, so answering them from cache would succeed where the
    // real tool errors out.
    #expect(SecretReference.parse("op://API-Keys/[CLI] N8N API Key/credential") == nil)
    #expect(SecretReference.parse("op://Kunden-Zugaenge/supabase | Norman/credential") == nil)
    #expect(SecretReference.parse("op://Employee/Token (rotiert)/credential") == nil)
    #expect(SecretReference.parse("op://Employee/Bliro/Sicherheitstoken für n8n") == nil)
    #expect(SecretReference.parse("op://Kunden-Zugänge/item/credential") == nil)
    #expect(SecretReference.parse("op://Employee/item/Cert ID, Client") == nil)

    // The set op does accept: letters, digits, space, _ - . =
    #expect(SecretReference.parse("op://API-Keys/n8n-demo api/valid from") != nil)
    #expect(SecretReference.parse("op://Kunden-Zugaenge/item_1.2/field=x") != nil)
}
