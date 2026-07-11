import Foundation

public struct OnePassword: Sendable {
    public let executableURL: URL

    public init(executableURL: URL = URL(fileURLWithPath: "/opt/homebrew/bin/op")) {
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
            process.waitUntilExit()
        } catch {
            throw OpCacheError.message("Could not run 1Password CLI: \(error.localizedDescription)")
        }

        let outputData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let message = String(decoding: errorData, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw OpCacheError.message(message.isEmpty ? "1Password CLI failed." : message)
        }
        return String(decoding: outputData, as: UTF8.self)
    }
}
