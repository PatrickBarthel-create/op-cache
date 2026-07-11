import Testing
@testable import OpCacheCore

@Test func cleanupContinuesAfterIndividualFailure() {
    var attempted: [String] = []
    let result = BatchCleanup.run(items: ["everlast", "broken", "private"]) { item in
        attempted.append(item)
        if item == "broken" {
            throw OpCacheError.message("simulated failure")
        }
    }

    #expect(attempted == ["everlast", "broken", "private"])
    #expect(result.succeeded == ["everlast", "private"])
    #expect(result.failed == [CleanupFailure(item: "broken", message: "simulated failure")])
}
