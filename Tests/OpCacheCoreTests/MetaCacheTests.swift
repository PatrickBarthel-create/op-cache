import Foundation
import Testing
@testable import OpCacheCore

private func makeTemporaryDirectory() -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("op-cache-meta-tests-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

@Test func storesAndReturnsListings() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let cache = MetaCache(directory: directory)

    #expect(cache.get(key: "cabc") == nil)
    try cache.put(key: "cabc", value: "[{\"id\":\"1\"}]")
    #expect(cache.get(key: "cabc") == "[{\"id\":\"1\"}]")
}

@Test func storesEntriesReadableOnlyByTheOwner() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let cache = MetaCache(directory: directory)

    try cache.put(key: "cabc", value: "listing")
    let path = directory.appendingPathComponent("cabc").path
    let permissions = try #require(
        FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber
    )
    #expect((permissions.uint16Value & 0o077) == 0)
}

@Test func ignoresEntriesOtherUsersCouldHaveWritten() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let cache = MetaCache(directory: directory)

    try cache.put(key: "cabc", value: "listing")
    let path = directory.appendingPathComponent("cabc").path
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)

    #expect(cache.get(key: "cabc") == nil)
}

@Test func clearDropsEverything() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let cache = MetaCache(directory: directory)

    try cache.put(key: "cone", value: "a")
    try cache.put(key: "ctwo", value: "b")
    #expect(cache.count() == 2)

    #expect(cache.clear() == 2)
    #expect(cache.get(key: "cone") == nil)
    #expect(cache.count() == 0)
}

@Test func skipsEntriesLargerThanTheLimit() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let cache = MetaCache(directory: directory)

    let oversized = String(repeating: "x", count: MetaCache.maximumEntryBytes + 1)
    try cache.put(key: "cbig", value: oversized)
    #expect(cache.get(key: "cbig") == nil)
}

@Test func recognisesLookupFailuresThatMeanACachedListingIsStale() {
    #expect(MetaCache.indicatesStaleLookup("\"Foo\" isn't an item. Specify the item"))
    #expect(MetaCache.indicatesStaleLookup("ERROR: no item matches \"Bar\""))
    #expect(MetaCache.indicatesStaleLookup("more than one item matches \"Bar\""))
    #expect(MetaCache.indicatesStaleLookup("vault not found"))

    #expect(!MetaCache.indicatesStaleLookup(""))
    #expect(!MetaCache.indicatesStaleLookup("authorization prompt dismissed"))
    #expect(!MetaCache.indicatesStaleLookup("could not connect to 1Password"))
}
