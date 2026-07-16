import Foundation

private final class DataCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func store(_ value: Data) {
        lock.lock()
        data = value
        lock.unlock()
    }

    func load() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}

public struct OnePassword: Sendable {
    public static let defaultSearchPaths = [
        "/opt/homebrew/bin/op",
        "/usr/local/bin/op",
    ]

    public static func locateExecutable() -> URL {
        let found = defaultSearchPaths.first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
        return URL(fileURLWithPath: found ?? defaultSearchPaths[0])
    }

    public let executableURL: URL

    public init(executableURL: URL = OnePassword.locateExecutable()) {
        self.executableURL = executableURL
    }

    public func authenticate(account: String) throws {
        _ = try run(["signin", "--account", account])
    }

    public func read(reference: String, account: String) throws -> String {
        try run(["read", "--account", account, "--no-newline", reference])
    }

    private func run(_ arguments: [String]) throws -> String {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw OpCacheError.message("1Password CLI not found at \(executableURL.path).")
        }

        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw OpCacheError.message("Could not run 1Password CLI: \(error.localizedDescription)")
        }

        let group = DispatchGroup()
        let outputCollector = DataCollector()
        let errorCollector = DataCollector()

        group.enter()
        DispatchQueue.global().async {
            outputCollector.store(stdout.fileHandleForReading.readDataToEndOfFile())
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errorCollector.store(stderr.fileHandleForReading.readDataToEndOfFile())
            group.leave()
        }

        process.waitUntilExit()
        group.wait()

        let outputData = outputCollector.load()
        let errorData = errorCollector.load()
        guard process.terminationStatus == 0 else {
            let message = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw OpCacheError.message(message.isEmpty ? "1Password CLI failed." : message)
        }
        return String(decoding: outputData, as: UTF8.self)
    }
}
