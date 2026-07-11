public struct UnlockArguments: Equatable, Sendable {
    public let profile: String
    public let ttl: String?
}

public struct RunArguments: Equatable, Sendable {
    public let profile: String
    public let only: Set<String>?
    public let command: [String]
}

public enum CLIArgumentParser {
    public static func parseUnlock(_ arguments: [String]) throws -> UnlockArguments {
        guard let profile = arguments.first, !profile.hasPrefix("-") else {
            throw OpCacheError.message("Usage: op-cache unlock <profile> [--ttl 8h]")
        }

        let options = Array(arguments.dropFirst())
        switch options.count {
        case 0:
            return UnlockArguments(profile: profile, ttl: nil)
        case 2 where options[0] == "--ttl":
            return UnlockArguments(profile: profile, ttl: options[1])
        default:
            throw OpCacheError.message(
                "Unknown or malformed unlock options. Usage: op-cache unlock <profile> [--ttl 8h]"
            )
        }
    }

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
