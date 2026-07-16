import Darwin
import Foundation
import Testing
@testable import OpCacheCore

@Test func recordsOneJSONObjectPerLine() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let log = AuditLog(url: url, warn: { _ in })

    log.record(sampleEvent(event: .unlock))
    log.record(sampleEvent(event: .run))

    let lines = try lineObjects(at: url)
    #expect(lines.count == 2)
    #expect(lines[0]["event"] as? String == "unlock")
    #expect(lines[1]["event"] as? String == "run")
}

@Test func recordsTheVaultReferenceButNeverTheValue() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    AuditLog(url: url, warn: { _ in }).record(sampleEvent(event: .run))

    let contents = try String(contentsOf: url, encoding: .utf8)
    #expect(contents.contains("op://Development/Cloudflare/credential"))
    // The value is never handed to the log, but assert on the raw text too:
    // this is the one property the whole feature stands or falls on.
    #expect(!contents.contains("super-secret-value"))
}

@Test func omitsChildArgumentsBecauseTheyCanCarrySecrets() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    AuditLog(url: url, warn: { _ in }).record(
        AuditEvent(
            event: .run,
            profile: "work",
            account: "example.1password.com",
            secrets: [],
            command: "/bin/sh",
            argumentCount: 2,
            caller: AuditCaller(pid: 1, path: "/bin/zsh")
        )
    )

    let line = try lineObjects(at: url)[0]
    #expect(line["command"] as? String == "/bin/sh")
    #expect(line["argumentCount"] as? Int == 2)
    #expect(line["arguments"] == nil)
}

@Test func createsTheLogPrivateToTheCurrentUser() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    AuditLog(url: url, warn: { _ in }).record(sampleEvent(event: .unlock))

    let mode = try #require(
        FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
    )
    #expect(mode.uint16Value & 0o077 == 0)
}

@Test func tightensPermissionsOnAnExistingLoosenedLog() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    let log = AuditLog(url: url, warn: { _ in })

    log.record(sampleEvent(event: .unlock))
    #expect(chmod(url.path, 0o644) == 0)
    log.record(sampleEvent(event: .run))

    let mode = try #require(
        FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
    )
    #expect(mode.uint16Value & 0o077 == 0)
}

@Test func rotatesOnceTheLogGrowsPastTheLimit() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
    try FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let oversized = Data(repeating: 0x61, count: AuditLog.maximumBytes + 1)
    try oversized.write(to: url)

    AuditLog(url: url, warn: { _ in }).record(sampleEvent(event: .run))

    let rotated = url.appendingPathExtension("1")
    #expect(FileManager.default.fileExists(atPath: rotated.path))
    #expect(try lineObjects(at: url).count == 1)
}

@Test func writesNothingWhenDisabled() throws {
    let url = temporaryLogURL()
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    let config = AuditConfig(enabled: false, path: url.path)
    #expect(config.resolvedURL() == nil)
    AuditLog(config: config, warn: { _ in }).record(sampleEvent(event: .run))

    #expect(!FileManager.default.fileExists(atPath: url.path))
}

@Test func defaultsToEnabledAtTheDefaultPath() {
    #expect(AuditConfig().resolvedURL() == AuditLog.defaultURL())
    #expect(AuditConfig(enabled: true, path: nil).resolvedURL() == AuditLog.defaultURL())
}

@Test func expandsATildeInTheConfiguredPath() throws {
    let resolved = try #require(AuditConfig(path: "~/audit.jsonl").resolvedURL())
    #expect(!resolved.path.contains("~"))
    #expect(resolved.path.hasSuffix("/audit.jsonl"))
}

@Test func warnsInsteadOfFailingWhenTheLogCannotBeWritten() throws {
    // A path whose parent is a file, so the directory can never be created.
    let blocker = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString)
    try Data("blocked".utf8).write(to: blocker)
    defer { try? FileManager.default.removeItem(at: blocker) }

    let warnings = Warnings()
    AuditLog(url: blocker.appendingPathComponent("audit.jsonl"), warn: { warnings.append($0) })
        .record(sampleEvent(event: .run))

    #expect(warnings.count() == 1)
}

@Test func decodesAConfigWithoutAnAuditSection() throws {
    let json = """
    {"defaultTTL":"8h","profiles":{"work":{"account":"a.1password.com","secrets":{"T":"op://v/i/f"}}}}
    """
    let config = try JSONDecoder().decode(AppConfig.self, from: Data(json.utf8))
    #expect(config.audit == nil)
    // A config written before this feature existed still logs by default.
    #expect((config.audit ?? AuditConfig()).isEnabled)
}

private final class Warnings: @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [String] = []

    func append(_ message: String) {
        lock.lock()
        messages.append(message)
        lock.unlock()
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return messages.count
    }
}

private func sampleEvent(event: AuditEvent.Kind) -> AuditEvent {
    AuditEvent(
        event: event,
        profile: "work",
        account: "example.1password.com",
        secrets: [
            AuditSecret(name: "CLOUDFLARE_API_TOKEN", reference: "op://Development/Cloudflare/credential")
        ],
        caller: AuditCaller(pid: 4242, path: "/bin/zsh")
    )
}

private func temporaryLogURL() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
        .appendingPathComponent("op-cache-audit.jsonl")
}

private func lineObjects(at url: URL) throws -> [[String: Any]] {
    try String(contentsOf: url, encoding: .utf8)
        .split(separator: "\n")
        .map { line in
            let object = try JSONSerialization.jsonObject(with: Data(line.utf8))
            guard let dictionary = object as? [String: Any] else {
                throw OpCacheError.message("Line is not a JSON object.")
            }
            return dictionary
        }
}
