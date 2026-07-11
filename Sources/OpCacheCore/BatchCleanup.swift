public struct CleanupFailure: Equatable, Sendable {
    public let item: String
    public let message: String
}

public struct CleanupResult: Equatable, Sendable {
    public let succeeded: [String]
    public let failed: [CleanupFailure]
}

public enum BatchCleanup {
    /// Attempts every item even when an earlier cleanup fails.
    public static func run(
        items: [String],
        operation: (String) throws -> Void
    ) -> CleanupResult {
        var succeeded: [String] = []
        var failed: [CleanupFailure] = []

        for item in items {
            do {
                try operation(item)
                succeeded.append(item)
            } catch {
                failed.append(CleanupFailure(item: item, message: error.localizedDescription))
            }
        }

        return CleanupResult(succeeded: succeeded, failed: failed)
    }
}
