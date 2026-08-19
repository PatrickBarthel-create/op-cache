import Foundation
import Testing
@testable import OpCacheCore

private let storedJSON = """
{
  "id": "i-n8n",
  "title": "n8n-demo api",
  "vault": { "id": "v-api", "name": "API-Keys" },
  "fields": [
    { "id": "username", "type": "STRING", "label": "user", "value": "admin" },
    { "id": "credential", "type": "CONCEALED", "label": "credential", "value": "tok,en" }
  ]
}
"""

private func makeResolver(store: [ItemCoordinate: String]) -> ItemResolver {
    let index = ItemIndex(
        builtAt: Date(timeIntervalSince1970: 0),
        accounts: [
            IndexedAccount(
                url: "everlastconsultinggmbh.1password.eu",
                aliases: ["everlastconsultinggmbh.1password.eu", "everlastconsultinggmbh"],
                vaults: [
                    IndexedVault(id: "v-api", name: "API-Keys", items: [
                        IndexedItem(id: "i-n8n", title: "n8n-demo api"),
                    ]),
                ]
            ),
        ]
    )
    return ItemResolver(loadItem: { store[$0] }, loadIndex: { index })
}

private let coordinate = ItemCoordinate(
    account: "everlastconsultinggmbh.1password.eu",
    vaultID: "v-api",
    itemID: "i-n8n"
)

@Test func answersTheSameSecretHoweverItIsAddressed() {
    let resolver = makeResolver(store: [coordinate: storedJSON])

    // One stored copy, four spellings: this is the whole point of keying on
    // where an item lives instead of on the argument vector.
    #expect(resolver.answer(for: ["read", "op://API-Keys/n8n-demo api/credential"]) == "tok,en\n")
    #expect(resolver.answer(for: ["read", "--account", "everlastconsultinggmbh", "op://API-Keys/n8n-demo api/credential"]) == "tok,en\n")
    #expect(resolver.answer(for: ["read", "op://v-api/i-n8n/credential"]) == "tok,en\n")
    #expect(resolver.answer(for: ["read", "--no-newline", "op://API-Keys/n8n-demo api/credential"]) == "tok,en")
}

@Test func answersItemGetShapesItCanReproduce() {
    let resolver = makeResolver(store: [coordinate: storedJSON])

    #expect(resolver.answer(for: ["item", "get", "n8n-demo api", "--format", "json"]) == storedJSON)
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--vault", "API-Keys", "--fields", "user", "--reveal"]) == "admin\n")
    // A concealed value holding a comma is quoted exactly as Go's csv writer does.
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--fields", "credential", "--reveal"]) == "\"tok,en\"\n")
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--fields", "label=credential", "--reveal"]) == "\"tok,en\"\n")
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--fields", "user,credential"]) == "admin,[use 'op item get i-n8n --reveal' to reveal]\n")
}

@Test func declinesRatherThanGuesses() {
    let resolver = makeResolver(store: [coordinate: storedJSON])

    // Not prefetched.
    #expect(resolver.answer(for: ["read", "op://API-Keys/other item/credential"]) == nil)
    // Field does not exist: op fails here, and an empty value would be a lie.
    #expect(resolver.answer(for: ["read", "op://API-Keys/n8n-demo api/nope"]) == nil)
    // `id=` is not a selector op understands.
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--fields", "id=username", "--reveal"]) == nil)
    // One unresolvable field in the list voids the whole record.
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--fields", "user,nope", "--reveal"]) == nil)
    // Shapes that were never measured.
    #expect(resolver.answer(for: ["item", "get", "i-n8n"]) == nil)
    #expect(resolver.answer(for: ["item", "get", "i-n8n", "--otp"]) == nil)
    #expect(resolver.answer(for: ["vault", "list"]) == nil)

    // An empty store: the index alone must never produce an answer.
    let empty = makeResolver(store: [:])
    #expect(empty.answer(for: ["read", "op://API-Keys/n8n-demo api/credential"]) == nil)
}
