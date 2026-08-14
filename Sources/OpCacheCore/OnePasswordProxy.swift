import Foundation

public struct OpResult: Sendable {
    public let status: Int32
    public let standardOutput: String
    public let standardError: String

    public init(status: Int32, standardOutput: String, standardError: String) {
        self.status = status
        self.standardOutput = standardOutput
        self.standardError = standardError
    }
}

private final class OutputCollector: @unchecked Sendable {
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

extension OnePassword {
    /// Runs `op` with the caller's stdio attached and returns its exit status.
    /// Used for everything that must never be cached, so those calls behave
    /// exactly as if the shim were not installed.
    public func passthrough(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// Runs `op` and captures both streams so the result can be cached.
    /// stderr is captured rather than suppressed and is replayed by the caller,
    /// which keeps 1Password's own error messages intact.
    public func capture(_ arguments: [String]) throws -> OpResult {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw OpCacheError.message("1Password CLI not found at \(executableURL.path).")
        }

        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardInput = FileHandle.standardInput
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw OpCacheError.message("Could not run 1Password CLI: \(error.localizedDescription)")
        }

        let group = DispatchGroup()
        let outputCollector = OutputCollector()
        let errorCollector = OutputCollector()

        // Both pipes must drain concurrently: a large `item list` fills the
        // buffer and deadlocks if read sequentially after waitUntilExit.
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

        return OpResult(
            status: process.terminationStatus,
            standardOutput: String(decoding: outputCollector.load(), as: UTF8.self),
            standardError: String(decoding: errorCollector.load(), as: UTF8.self)
        )
    }
}
