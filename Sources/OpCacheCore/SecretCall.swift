import Foundation

/// What an `op` command line is asking for, when this cache can tell.
///
/// Everlast fork only. Parsing is a strict whitelist: every flag must be one
/// that was measured, and anything unrecognised yields nil so the call reaches
/// `op` untouched. The cost of being wrong here is a wrong secret, while the
/// cost of bailing out is one approval prompt.
public enum SecretCall: Equatable, Sendable {
    /// `op read op://vault/item[/section]/field`
    case read(reference: SecretReference, account: String?, noNewline: Bool)
    /// `op item get <item> [--vault v] --format json`
    case itemJSON(item: String, vault: String?, account: String?)
    /// `op item get <item> [--vault v] --fields a,b [--reveal]`
    case itemFields(item: String, vault: String?, account: String?, specs: [String], reveal: Bool)

    public var account: String? {
        switch self {
        case let .read(_, account, _): account
        case let .itemJSON(_, _, account): account
        case let .itemFields(_, _, account, _, _): account
        }
    }

    /// Flags that take a value and are understood. A flag outside this table
    /// makes the whole call unparseable on purpose.
    private static let valueFlags: Set<String> = ["--account", "--vault", "--fields", "--format"]
    /// Value-less flags that do not change what is returned.
    private static let benignFlags: Set<String> = ["--reveal"]

    public static func parse(_ arguments: [String]) -> SecretCall? {
        guard let verb = arguments.first else { return nil }
        switch verb {
        case "read":
            return parseRead(Array(arguments.dropFirst()))
        case "item":
            guard arguments.count > 1, arguments[1] == "get" else { return nil }
            return parseItemGet(Array(arguments.dropFirst(2)))
        default:
            return nil
        }
    }

    // MARK: - read

    private static func parseRead(_ arguments: [String]) -> SecretCall? {
        var account: String?
        var noNewline = false
        var positionals: [String] = []
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--no-newline", "-n":
                noNewline = true
            case "--account":
                guard let value = value(after: index, in: arguments) else { return nil }
                account = value
                index += 1
            default:
                if let value = inlineValue(of: "--account", in: argument) {
                    account = value
                } else if argument.hasPrefix("-") {
                    // --out-file writes a file, --file-mode changes it, and
                    // anything unknown might do either.
                    return nil
                } else {
                    positionals.append(argument)
                }
            }
            index += 1
        }

        guard positionals.count == 1,
              let reference = SecretReference.parse(positionals[0]) else { return nil }
        return .read(reference: reference, account: account, noNewline: noNewline)
    }

    // MARK: - item get

    private static func parseItemGet(_ arguments: [String]) -> SecretCall? {
        var account: String?
        var vault: String?
        var fields: String?
        var format: String?
        var reveal = false
        var positionals: [String] = []
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            if benignFlags.contains(argument) {
                if argument == "--reveal" { reveal = true }
                index += 1
                continue
            }
            if valueFlags.contains(argument) {
                guard let value = value(after: index, in: arguments) else { return nil }
                switch argument {
                case "--account": account = value
                case "--vault": vault = value
                case "--fields": fields = value
                case "--format": format = value
                default: return nil
                }
                index += 2
                continue
            }
            if argument.hasPrefix("-") {
                var matched = false
                for flag in valueFlags {
                    if let value = inlineValue(of: flag, in: argument) {
                        switch flag {
                        case "--account": account = value
                        case "--vault": vault = value
                        case "--fields": fields = value
                        case "--format": format = value
                        default: return nil
                        }
                        matched = true
                        break
                    }
                }
                // --otp is time-based, --share-link mutates, --format=yaml is
                // a shape that was never measured.
                guard matched else { return nil }
                index += 1
                continue
            }
            positionals.append(argument)
            index += 1
        }

        guard positionals.count == 1 else { return nil }
        let item = positionals[0]

        // `op item get op://…` is a different addressing mode whose output
        // was never measured here; leave it to op.
        guard !item.hasPrefix("op://") else { return nil }

        if let fields {
            // Field selection combined with JSON is 0.2% of measured calls and
            // its own output shape; not worth the risk of rendering it.
            guard format == nil else { return nil }
            let specs = fields.split(separator: ",").map(String.init)
            guard !specs.isEmpty else { return nil }
            return .itemFields(item: item, vault: vault, account: account, specs: specs, reveal: reveal)
        }

        // The default human format prints relative timestamps ("1 month ago"),
        // which cannot be reproduced from a stored copy.
        guard format == "json" else { return nil }
        return .itemJSON(item: item, vault: vault, account: account)
    }

    // MARK: - Helpers

    private static func value(after index: Int, in arguments: [String]) -> String? {
        let next = index + 1
        guard next < arguments.count, !arguments[next].hasPrefix("--") else { return nil }
        return arguments[next]
    }

    private static func inlineValue(of flag: String, in argument: String) -> String? {
        let prefix = flag + "="
        guard argument.hasPrefix(prefix) else { return nil }
        let value = String(argument.dropFirst(prefix.count))
        return value.isEmpty ? nil : value
    }
}
