import Testing
@testable import OpCacheCore

private let itemJSON = """
{
  "id": "abc123",
  "title": "Direma Cockpit",
  "vault": { "id": "v1", "name": "Kunden-Zugaenge" },
  "fields": [
    { "id": "username", "type": "STRING", "label": "CF_ACCESS_TEAM_DOMAIN", "value": "team.example.com" },
    { "id": "password", "type": "CONCEALED", "label": "URL", "value": "s3cr3t" },
    { "id": "name", "type": "STRING", "label": "Name" },
    { "id": "port", "type": "STRING", "label": "Port", "value": "5432",
      "section": { "id": "sec1", "label": "Server" } }
  ]
}
"""

@Test func findsFieldsByIDAndLabelCaseInsensitively() throws {
    let payload = try #require(ItemPayload.decode(itemJSON))
    // Measured against op: both the ID and the label resolve, either case.
    #expect(payload.field(named: "username")?.value == "team.example.com")
    #expect(payload.field(named: "CF_ACCESS_TEAM_DOMAIN")?.value == "team.example.com")
    #expect(payload.field(named: "cf_access_team_domain")?.value == "team.example.com")
    #expect(payload.field(named: "URL")?.value == "s3cr3t")
    #expect(payload.field(named: "gibtsnicht") == nil)
}

@Test func honoursSectionsAndRefusesAmbiguity() throws {
    let payload = try #require(ItemPayload.decode(itemJSON))
    #expect(payload.field(named: "Port", section: "Server")?.value == "5432")
    #expect(payload.field(named: "Port", section: "Elsewhere") == nil)

    // One name meaning two fields is what op reports as an error; answering
    // either one would hand back the wrong secret.
    let ambiguous = """
    {"id":"x","title":"t","fields":[
      {"id":"username","type":"STRING","label":"other","value":"a"},
      {"id":"other","type":"STRING","label":"username","value":"b"}]}
    """
    let clash = try #require(ItemPayload.decode(ambiguous))
    #expect(clash.candidates(for: "username").count == 2)
    #expect(clash.field(named: "username") == nil)
}

@Test func rendersReadOutputByteForByte() throws {
    let payload = try #require(ItemPayload.decode(itemJSON))
    let field = try #require(payload.field(named: "username"))
    #expect(payload.renderRead(field: field, noNewline: false) == "team.example.com\n")
    #expect(payload.renderRead(field: field, noNewline: true) == "team.example.com")

    // A field that exists but holds no value prints as an empty line.
    let empty = try #require(payload.field(named: "Name"))
    #expect(payload.renderRead(field: empty, noNewline: false) == "\n")
}

@Test func doesNotDoubleTheNewlineAValueAlreadyHas() throws {
    // Measured on a notes field ending in two blank lines: op printed 754
    // bytes, an unconditional append produced 755.
    let json = #"{"id":"i","title":"t","fields":[{"id":"notesPlain","type":"STRING","label":"notesPlain","value":"zeile\n\n"}]}"#
    let payload = try #require(ItemPayload.decode(json))
    let field = try #require(payload.field(named: "notesPlain"))
    #expect(payload.renderRead(field: field, noNewline: false) == "zeile\n\n")
    #expect(payload.renderRead(field: field, noNewline: true) == "zeile\n\n")
}

@Test func readsURLsFromTheDocument() throws {
    let json = #"{"id":"i","title":"t","urls":[{"label":"website","primary":true,"href":"https://telnyx.com"},{"href":"portal.telnyx.com"}],"fields":[]}"#
    let payload = try #require(ItemPayload.decode(json))
    #expect(payload.urls == ["https://telnyx.com", "portal.telnyx.com"])
}

@Test func rendersFieldsWithConcealmentAndCSVQuoting() throws {
    let payload = try #require(ItemPayload.decode(itemJSON))
    let visible = try #require(payload.field(named: "username"))
    let concealed = try #require(payload.field(named: "URL"))

    #expect(payload.renderFields([visible], reveal: true) == "team.example.com\n")
    #expect(payload.renderFields([concealed], reveal: true) == "s3cr3t\n")
    // Without --reveal op names the item ID, never the caller's spelling.
    #expect(
        payload.renderFields([visible, concealed], reveal: false)
            == "team.example.com,[use 'op item get abc123 --reveal' to reveal]\n"
    )
}

@Test func quotesOnlyWhatGoWouldQuote() {
    #expect(CSVRecord.encode(["plain", "value"]) == "plain,value")
    #expect(CSVRecord.encode(["a,b"]) == "\"a,b\"")
    #expect(CSVRecord.encode(["say \"hi\""]) == "\"say \"\"hi\"\"\"")
    #expect(CSVRecord.encode(["line1\nline2"]) == "\"line1\nline2\"")
    #expect(CSVRecord.encode([" leading"]) == "\" leading\"")
    #expect(CSVRecord.encode([""]) == "")
}
