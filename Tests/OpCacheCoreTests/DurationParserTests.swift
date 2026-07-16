import Foundation
import Testing
@testable import OpCacheCore

@Test func parsesSupportedDurations() throws {
    #expect(try DurationParser.parse("30m") == 1_800)
    #expect(try DurationParser.parse("1h") == 3_600)
    #expect(try DurationParser.parse("1d") == 86_400)
    // Everlast fork: the cap is 3d, where upstream stops at 1d.
    #expect(try DurationParser.parse("3d") == 259_200)
}

@Test func rejectsInvalidOrExcessiveDurations() {
    #expect(throws: (any Error).self) { try DurationParser.parse("0h") }
    #expect(throws: (any Error).self) { try DurationParser.parse("4d") }
    #expect(throws: (any Error).self) { try DurationParser.parse("forever") }
}
