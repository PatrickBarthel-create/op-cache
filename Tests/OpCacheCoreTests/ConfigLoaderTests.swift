import Darwin
import Foundation
import Testing
@testable import OpCacheCore

@Test func loadsPrivateConfigFile() throws {
    let url = try temporaryConfig(mode: 0o600)
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    let config = try ConfigLoader.load(from: url)
    #expect(config.defaultTTL == "1h")
    #expect(config.profiles["private"]?.secrets["TOKEN"] == "op://vault/item/field")
}

@Test func rejectsConfigReadableByOtherUsers() throws {
    let url = try temporaryConfig(mode: 0o644)
    defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

    #expect(throws: (any Error).self) { try ConfigLoader.load(from: url) }
}

private func temporaryConfig(mode: mode_t) throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appendingPathComponent("config.json")
    let config = AppConfig(
        defaultTTL: "1h",
        profiles: [
            "private": ProfileConfig(
                account: "my.1password.eu",
                secrets: ["TOKEN": "op://vault/item/field"]
            )
        ]
    )
    try JSONEncoder().encode(config).write(to: url, options: .atomic)
    guard chmod(url.path, mode) == 0 else {
        throw OpCacheError.message("chmod failed")
    }
    return url
}
