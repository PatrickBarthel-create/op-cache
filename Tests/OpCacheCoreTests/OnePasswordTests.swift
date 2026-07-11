import Darwin
import Foundation
import Testing
@testable import OpCacheCore

@Test func readReturnsStubOutputAndPassesArguments() throws {
    let stub = try stubExecutable(script: """
    #!/bin/sh
    echo "args:$@" >> "@LOG@"
    printf 'stub-secret'
    """)
    defer { try? FileManager.default.removeItem(at: stub.directory) }

    let onePassword = OnePassword(executableURL: stub.url)
    let value = try onePassword.read(reference: "op://vault/item/field", account: "my.1password.eu")

    #expect(value == "stub-secret")
    let log = try String(contentsOf: stub.log, encoding: .utf8)
    #expect(log.contains("read --account my.1password.eu --no-newline op://vault/item/field"))
}

@Test func failingCliSurfacesStderrMessage() throws {
    let stub = try stubExecutable(script: """
    #!/bin/sh
    echo 'authorization denied' >&2
    exit 1
    """)
    defer { try? FileManager.default.removeItem(at: stub.directory) }

    let onePassword = OnePassword(executableURL: stub.url)
    #expect(throws: OpCacheError.message("authorization denied")) {
        try onePassword.read(reference: "op://vault/item/field", account: "my.1password.eu")
    }
}

@Test func missingExecutableFailsLoudly() {
    let onePassword = OnePassword(executableURL: URL(fileURLWithPath: "/nonexistent/op"))
    #expect(throws: (any Error).self) {
        try onePassword.read(reference: "op://vault/item/field", account: "my.1password.eu")
    }
}

@Test func largeOutputIsDrainedWithoutDeadlock() throws {
    let stub = try stubExecutable(script: """
    #!/bin/sh
    head -c 200000 /dev/zero | tr '\\0' x
    """)
    defer { try? FileManager.default.removeItem(at: stub.directory) }

    let onePassword = OnePassword(executableURL: stub.url)
    let value = try onePassword.read(reference: "op://vault/item/field", account: "my.1password.eu")
    #expect(value.utf8.count == 200000)
}

private func stubExecutable(script: String) throws -> (directory: URL, url: URL, log: URL) {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appendingPathComponent("op")
    let log = directory.appendingPathComponent("stub.log")
    let rendered = script.replacingOccurrences(of: "@LOG@", with: log.path)
    try rendered.write(to: url, atomically: true, encoding: .utf8)
    guard chmod(url.path, 0o755) == 0 else {
        throw OpCacheError.message("chmod failed")
    }
    return (directory, url, log)
}
