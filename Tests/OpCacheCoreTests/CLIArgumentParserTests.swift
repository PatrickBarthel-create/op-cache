import Testing
@testable import OpCacheCore

@Test func parsesStrictUnlockArguments() throws {
    #expect(try CLIArgumentParser.parseUnlock(["private"]) == UnlockArguments(profile: "private", ttl: nil))
    #expect(try CLIArgumentParser.parseUnlock(["private", "--ttl", "8h"]) == UnlockArguments(profile: "private", ttl: "8h"))
}

@Test func rejectsUnknownOrMalformedUnlockOptions() {
    #expect(throws: (any Error).self) { try CLIArgumentParser.parseUnlock(["private", "--tll", "1h"]) }
    #expect(throws: (any Error).self) { try CLIArgumentParser.parseUnlock(["private", "--ttl"]) }
    #expect(throws: (any Error).self) { try CLIArgumentParser.parseUnlock(["--ttl", "1h"]) }
}

@Test func parsesStrictRunArguments() throws {
    let parsed = try CLIArgumentParser.parseRun([
        "private", "--only", "TOKEN_A,TOKEN_B", "--", "npm", "run", "deploy",
    ])
    #expect(parsed.profile == "private")
    #expect(parsed.only == ["TOKEN_A", "TOKEN_B"])
    #expect(parsed.command == ["npm", "run", "deploy"])
}

@Test func rejectsMisspelledOrMalformedRunOptions() {
    #expect(throws: (any Error).self) {
        try CLIArgumentParser.parseRun(["private", "--onyl", "TOKEN", "--", "true"])
    }
    #expect(throws: (any Error).self) {
        try CLIArgumentParser.parseRun(["private", "--unexpected", "--", "true"])
    }
    #expect(throws: (any Error).self) {
        try CLIArgumentParser.parseRun(["private", "--only", "", "--", "true"])
    }
}
