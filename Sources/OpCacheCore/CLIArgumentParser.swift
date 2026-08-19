public struct UnlockArguments: Equatable, Sendable {
    /// nil in `--all` mode, which unlocks every account rather than a profile.
    public let profile: String?
    public let ttl: String?
    /// Everlast fork only: prefetch every item of every vault.
    public let all: Bool
    /// Everlast fork only: limit `--all` to these `op --account` aliases.
    public let accounts: [String]?

    public init(profile: String? = nil, ttl: String? = nil, all: Bool = false, accounts: [String]? = nil) {
        self.profile = profile
        self.ttl = ttl
        self.all = all
        self.accounts = accounts
    }
}

public struct RunArguments: Equatable, Sendable {
    public let profile: String
    public let only: Set<String>?
    public let command: [String]
}

public enum CLIArgumentParser {
    public static func parseUnlock(_ arguments: [String]) throws -> UnlockArguments {
        if arguments.contains("--all") {
            return try parseUnlockAll(arguments)
        }

        guard let profile = arguments.first, !profile.hasPrefix("-") else {
            throw OpCacheError.message(usage)
        }

        let options = Array(arguments.dropFirst())
        switch options.count {
        case 0:
            return UnlockArguments(profile: profile, ttl: nil)
        case 2 where options[0] == "--ttl":
            return UnlockArguments(profile: profile, ttl: options[1])
        default:
            throw OpCacheError.message("Unknown or malformed unlock options. \(usage)")
        }
    }

    /// Everlast fork only. `--all` takes no profile: the scope is every
    /// account `op` knows, optionally narrowed with `--account`.
    private static func parseUnlockAll(_ arguments: [String]) throws -> UnlockArguments {
        var ttl: String?
        var accounts: [String]?
        var index = 0

        while index < arguments.count {
            switch arguments[index] {
            case "--all":
                index += 1
            case "--ttl":
                guard index + 1 < arguments.count, !arguments[index + 1].hasPrefix("-") else {
                    throw OpCacheError.message("--ttl requires a duration, e.g. --ttl 3d.")
                }
                ttl = arguments[index + 1]
                index += 2
            case "--account":
                guard index + 1 < arguments.count, !arguments[index + 1].hasPrefix("-") else {
                    throw OpCacheError.message("--account requires an account alias.")
                }
                let names = arguments[index + 1].split(separator: ",").map(String.init)
                guard !names.isEmpty else {
                    throw OpCacheError.message("--account requires a non-empty comma-separated list.")
                }
                accounts = names
                index += 2
            default:
                throw OpCacheError.message("Unknown or malformed unlock options. \(usage)")
            }
        }

        return UnlockArguments(profile: nil, ttl: ttl, all: true, accounts: accounts)
    }

    private static let usage = """
        Usage: op-cache unlock <profile> [--ttl 8h]
               op-cache unlock --all [--ttl 3d] [--account <alias>[,<alias>]]
        """

    public static func parseRun(_ arguments: [String]) throws -> RunArguments {
        guard let separator = arguments.firstIndex(of: "--"), separator > 0 else {
            throw OpCacheError.message(
                "Usage: op-cache run <profile> [--only NAME,NAME] -- <command> [args...]"
            )
        }

        let options = Array(arguments[..<separator])
        let command = Array(arguments[(separator + 1)...])
        guard let profile = options.first, !profile.hasPrefix("-"), !command.isEmpty else {
            throw OpCacheError.message("A profile and command are required.")
        }

        let optionTail = Array(options.dropFirst())
        let only: Set<String>?
        switch optionTail.count {
        case 0:
            only = nil
        case 2 where optionTail[0] == "--only":
            let names = Set(optionTail[1].split(separator: ",").map(String.init))
            guard !names.isEmpty else {
                throw OpCacheError.message("--only requires a non-empty comma-separated list.")
            }
            only = names
        default:
            throw OpCacheError.message(
                "Unknown or malformed run options. Usage: op-cache run <profile> " +
                "[--only NAME,NAME] -- <command> [args...]"
            )
        }

        return RunArguments(profile: profile, only: only, command: command)
    }
}
