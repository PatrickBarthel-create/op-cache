import Foundation
import Testing
@testable import OpCacheCore

@Test func parsesSupportedDurations() throws {
    #expect(try DurationParser.parse("30m") == 1_800)
    #expect(try DurationParser.parse("1h") == 3_600)
    #expect(try DurationParser.parse("1d") == 86_400)
}

@Test func rejectsInvalidOrExcessiveDurations() {
    #expect(throws: (any Error).self) { try DurationParser.parse("0h") }
    #expect(throws: (any Error).self) { try DurationParser.parse("2d") }
    #expect(throws: (any Error).self) { try DurationParser.parse("forever") }
}
