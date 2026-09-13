import Foundation
import Testing
@testable import OpCacheCore

@Test func classifiesSecretReads() {
    #expect(ProxyClassifier.classify(["read", "op://Employee/pat/credential"]).kind == .secret)
    #expect(ProxyClassifier.classify(["item", "get", "GitHub", "--fields", "credential"]).kind == .secret)
}

@Test func classifiesMetadataListings() {
    #expect(ProxyClassifier.classify(["item", "list"]).kind == .metadata)
    #expect(ProxyClassifier.classify(["vault", "list", "--format", "json"]).kind == .metadata)
    #expect(ProxyClassifier.classify(["whoami"]).kind == .metadata)
    #expect(ProxyClassifier.classify(["account", "list"]).kind == .metadata)
}

@Test func prefersTheLongestSubcommandMatch() {
    // "item template list" is metadata even though "item get" is a secret
    // command and "item" alone means nothing.
    let call = ProxyClassifier.classify(["item", "template", "list"])
    #expect(call.kind == .metadata)
    #expect(call.subcommand == "item template list")
}

@Test func neverCachesTimeBasedOrInteractiveCalls() {
    // A cached one-time password is wrong within 30 seconds.
    #expect(ProxyClassifier.classify(["item", "get", "GitHub", "--otp"]).kind == .passthrough)
    #expect(ProxyClassifier.classify(["signin"]).kind == .passthrough)
    #expect(ProxyClassifier.classify(["inject", "-i", "in", "-o", "out"]).kind == .passthrough)
    #expect(ProxyClassifier.classify(["run", "--", "env"]).kind == .passthrough)
    #expect(ProxyClassifier.classify(["document", "get", "spec"]).kind == .passthrough)
}

@Test func treatsWritesAsInvalidating() {
    #expect(ProxyClassifier.classify(["item", "create", "--title", "New"]).kind == .mutating)
    #expect(ProxyClassifier.classify(["item", "edit", "GitHub", "password=x"]).kind == .mutating)
    #expect(ProxyClassifier.classify(["item", "delete", "GitHub"]).kind == .mutating)
    #expect(ProxyClassifier.classify(["vault", "create", "New"]).kind == .mutating)
}

@Test func doesNotMistakeAFlagValueForASubcommand() {
    // Without value-aware flag skipping, "get" here would be read as the verb.
    let call = ProxyClassifier.classify(["--account", "get", "item", "list"])
    #expect(call.kind == .metadata)
    #expect(call.subcommand == "item list")
}

@Test func classifiesUnknownCommandsAsPassthrough() {
    #expect(ProxyClassifier.classify(["something", "new"]).kind == .passthrough)
    #expect(ProxyClassifier.classify([]).kind == .passthrough)
    #expect(ProxyClassifier.classify(["--help"]).kind == .passthrough)
}

@Test func cacheKeysDistinguishArgumentsThatChangeTheOutput() {
    let plain = ProxyClassifier.cacheKey(["read", "op://Employee/pat/credential"])
    let noNewline = ProxyClassifier.cacheKey(["read", "--no-newline", "op://Employee/pat/credential"])
    let other = ProxyClassifier.cacheKey(["read", "op://Employee/other/credential"])

    #expect(plain != noNewline)
    #expect(plain != other)
    #expect(plain == ProxyClassifier.cacheKey(["read", "op://Employee/pat/credential"]))
}

@Test func cacheKeysAreValidKeychainAndFileNames() {
    let key = ProxyClassifier.cacheKey(["read", "op://Employee/pat/credential"])
    // Leading letter, hex only: safe as a file name and as a profile-style
    // identifier, and it carries no argument text.
    #expect(key.range(of: "^c[0-9a-f]{64}$", options: .regularExpression) != nil)
}

@Test func passthroughCallsCarryNoCacheKey() {
    #expect(ProxyClassifier.classify(["signin"]).key == nil)
    #expect(ProxyClassifier.classify(["item", "create"]).key == nil)
}

@Test func namesWhatTheCallAsksFor() {
    #expect(ProxyClassifier.classify(["read", "op://Employee/pat/credential"]).subject
        == "op://Employee/pat/credential")
    #expect(ProxyClassifier.classify(["item", "get", "GitHub", "--fields", "credential"]).subject
        == "GitHub")
    // The vault disambiguates two items that share a name.
    #expect(ProxyClassifier.classify(["item", "get", "GitHub", "--vault", "Employee"]).subject
        == "Employee/GitHub")
    #expect(ProxyClassifier.classify(["item", "get", "--vault=Employee", "GitHub"]).subject
        == "Employee/GitHub")
    // A flag value is never mistaken for the operand.
    #expect(ProxyClassifier.classify(["read", "--account", "everlast", "op://E/i/f"]).subject
        == "op://E/i/f")
    // A call that names nothing has no subject.
    #expect(ProxyClassifier.classify(["vault", "list"]).subject == nil)
    #expect(ProxyClassifier.classify(["whoami"]).subject == nil)
    // Never cached, never named.
    #expect(ProxyClassifier.classify(["item", "get", "GitHub", "--otp"]).subject == nil)
}
