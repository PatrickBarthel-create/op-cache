import CryptoKit
import Foundation

/// How a single `op` invocation may be cached.
///
/// Everlast fork only. Upstream caches a curated allowlist of secrets and
/// nothing else; this classifies arbitrary `op` command lines so a shim can
/// answer them from cache instead of triggering biometric approval per call.
public enum CallKind: String, Sendable, Equatable {
    /// Returns secret material. Cached in the Keychain under the profile TTL.
    case secret
    /// Returns names, IDs, and structure but no secret field values. Cached on
    /// disk without expiry; invalidated by writes and by lookup failures.
    case metadata
    /// Never cached: mutating, interactive, time-based, or streaming.
    case passthrough
    /// Not cached, and additionally invalidates the metadata cache afterwards.
    case mutating
}

public struct ClassifiedCall: Equatable, Sendable {
    public let kind: CallKind
    /// Stable cache identifier for this exact invocation, or nil when the call
    /// is never cached.
    public let key: String?
    /// Leading subcommand path, e.g. "item get". Recorded in the audit log so
    /// the log stays readable without ever holding argument values.
    public let subcommand: String
    /// What the call asks for, in the caller's own spelling: an `op://`
    /// reference, or an item name or ID with its vault where one was given.
    /// Recorded so the log answers "which secret", not just "how many".
    /// Never a field value - `op` takes references and names on the command
    /// line, never secret material, and `--otp` is classified passthrough.
    public let subject: String?

    public init(kind: CallKind, key: String?, subcommand: String, subject: String? = nil) {
        self.kind = kind
        self.key = key
        self.subcommand = subcommand
        // A call that names no operand still did something: `op inject -i
        // file` reads references from the file, `op item list` enumerates a
        // vault. The subcommand stands in, so a watcher counting "what asked"
        // sees the call rather than a blank. Nothing to fall back on for a
        // bare `op --version`, and that is fine: it reaches nothing.
        self.subject = subject ?? (subcommand.isEmpty ? nil : subcommand)
    }
}

public enum ProxyClassifier {
    /// Flags that make an otherwise cacheable call uncacheable, regardless of
    /// subcommand.
    private static let neverCacheFlags: Set<String> = [
        "--otp",           // time-based, a cached value is wrong within 30s
        "--session",       // caller manages its own session
        "--watch",         // streams
        "--share-link",    // creates a share link in 1Password: a side effect
        "-",               // stdin
    ]

    /// Verbs that change state in 1Password. Never cached, and they make the
    /// metadata cache stale, so the proxy drops it after these succeed.
    private static let mutatingVerbs: Set<String> = [
        "create", "edit", "delete", "add", "remove", "update",
        "grant", "revoke", "confirm", "suspend", "reactivate", "move",
        "archive", "restore", "share", "provision",
    ]

    /// Top-level commands that are never cached: they authenticate, mutate,
    /// spawn children, stream, or write files.
    private static let passthroughCommands: Set<String> = [
        "signin", "signout", "inject", "run", "plugin", "connect",
        "service-account", "events-api", "update", "completion", "document",
    ]

    /// Read-only commands whose output holds no secret field values.
    /// `item get` is deliberately absent: it can reveal fields.
    private static let metadataCommands: Set<String> = [
        "whoami",
        "account list", "account get",
        "vault list", "vault get",
        "item list", "item template list", "item template get",
        "user list", "user get",
        "group list", "group get",
        "events-api list",
    ]

    /// Commands that return secret material.
    private static let secretCommands: Set<String> = [
        "read",
        "item get",
    ]

    public static func classify(_ arguments: [String]) -> ClassifiedCall {
        // Once the leading words form a known subcommand, what follows is an
        // operand even if it happens to be spelled like a verb: an item named
        // "edit" fetched with `item get edit` must not read as a write and
        // wipe the cache.
        let leading = leadingVerbs(arguments)
        let verbs = knownVerbCount(leading).map { Array(leading.prefix($0)) } ?? leading
        let subcommand = verbs.joined(separator: " ")

        // Global help/version never reach the network and never prompt, and
        // they name nothing: a help call is not a request for an item.
        if arguments.isEmpty || arguments.contains("--help") || arguments.contains("-h")
            || arguments.contains("--version") {
            return ClassifiedCall(kind: .passthrough, key: nil, subcommand: "")
        }

        // Commands that spawn, stream or update the CLI come first: the words
        // after `op run --` belong to the child, and `op update` updates op,
        // not an item. Neither is a write to 1Password.
        if let first = verbs.first, passthroughCommands.contains(first) {
            // Documents are items: `document delete` is a write and is handled
            // below. Everything else under a passthrough command is not.
            // The verb sits right after `document`; a document merely named
            // like one (`document get delete`) is an operand.
            let writesADocument = first == "document"
                && verbs.dropFirst().first.map { mutatingVerbs.contains($0) } == true
            if !writesADocument {
                let named = passthroughWithOperand.contains(subcommand)
                return ClassifiedCall(
                    kind: .passthrough, key: nil, subcommand: subcommand,
                    subject: named ? subject(arguments, verbCount: verbs.count) : reference(arguments)
                )
            }
        }

        if verbs.contains(where: { mutatingVerbs.contains($0) }) {
            return ClassifiedCall(
                kind: .mutating, key: nil, subcommand: subcommand, subject: reference(arguments)
            )
        }

        // `--session=TOKEN` is the same flag as `--session TOKEN` and must not
        // slip past into the cache.
        // Three spellings ask for a one-time code: `--otp`, a reference with
        // `?attribute=otp`, and `--fields type=otp`. All three are time-based.
        if arguments.contains(where: { argument in
            neverCacheFlags.contains(argument)
                || neverCacheFlags.contains(where: { argument.hasPrefix($0 + "=") })
                || argument.lowercased().contains("attribute=otp")
                || argument.lowercased().contains("type=otp")
        }) {
            return ClassifiedCall(
                kind: .passthrough, key: nil, subcommand: subcommand,
                subject: knownVerbCount(verbs).map { subject(arguments, verbCount: $0) }
                    ?? reference(arguments)
            )
        }

        // Longest match first so "item template list" wins over "item".
        for candidate in prefixes(of: verbs) where secretCommands.contains(candidate) {
            return ClassifiedCall(
                kind: .secret,
                key: cacheKey(arguments),
                subcommand: candidate,
                subject: subject(arguments, verbCount: candidate.split(separator: " ").count)
            )
        }
        for candidate in prefixes(of: verbs) where metadataCommands.contains(candidate) {
            return ClassifiedCall(
                kind: .metadata,
                key: cacheKey(arguments),
                subcommand: candidate,
                subject: subject(arguments, verbCount: candidate.split(separator: " ").count)
            )
        }

        return ClassifiedCall(kind: .passthrough, key: nil, subcommand: subcommand)
    }

    /// The non-flag tokens at the front of the command line, which is where
    /// `op` puts its subcommand path.
    private static func leadingVerbs(_ arguments: [String]) -> [String] {
        var verbs: [String] = []
        var index = 0
        while index < arguments.count, verbs.count < 3 {
            let argument = arguments[index]
            // `--` ends op's own arguments; what follows is a child command.
            if argument == "--" { break }
            if argument.hasPrefix("-") {
                // A flag that takes a value swallows the next token, which must
                // not be mistaken for a subcommand.
                if !argument.contains("="), index + 1 < arguments.count,
                   flagTakesValue(argument) {
                    index += 1
                }
                index += 1
                continue
            }
            // The subcommand path ends at the first word `op` does not know as
            // one. Past it come operands, and `item edit password=x` puts a
            // secret third - the subcommand is written to the audit log, so it
            // must never reach that far.
            guard commandWords.contains(argument) else { break }
            verbs.append(argument)
            index += 1
        }
        return verbs
    }

    /// Every word that can appear in a subcommand path.
    private static let commandWords: Set<String> = {
        var words = mutatingVerbs.union(passthroughCommands)
        for command in metadataCommands.union(secretCommands) {
            for word in command.split(separator: " ") { words.insert(String(word)) }
        }
        return words
    }()

    /// Flags that take a value in op 2.34. `--iso-timestamps` and
    /// `--include-archive` are boolean there and were wrongly listed before:
    /// each swallowed the flag after it, so `--iso-timestamps --session TOKEN`
    /// turned the session token into an operand - and into the audit log.
    private static func flagTakesValue(_ flag: String) -> Bool {
        [
            "--account", "--vault", "--fields", "--format", "--session",
            "--cache-key", "--config", "--encoding",
            "--out-file", "--file-mode", "--categories", "--tags",
            // Filters of the listings. A value here that happens to be a
            // command word would otherwise be read as a verb.
            "--group", "--user", "--permission", "--output",
            // Short forms op documents. `-o file` before the reference would
            // otherwise make the file name the subject.
            "-o", "-i", "-t", "-c",
        ].contains(flag)
    }

    /// Passthrough commands whose operand is worth naming: `document get`
    /// reads secret material like `item get` does, only it is never cached.
    private static let passthroughWithOperand: Set<String> = ["document get"]

    /// Subcommands that take no operand at all. Whatever follows them is a
    /// mistake, and a mistyped command line is exactly the one that carries
    /// something meant for another program.
    private static let operandlessCommands: Set<String> = [
        "whoami", "account list", "account get", "vault list", "item list", "item template list",
        "user list", "group list", "events-api list",
    ]

    /// Values the caller handed to flags. A subject that equals one of them is
    /// a flag value in disguise, whatever parsing mistake let it through.
    private static func flagValues(_ arguments: [String]) -> Set<String> {
        var values: Set<String> = []
        for (index, argument) in arguments.enumerated() where argument.hasPrefix("-") {
            if let equals = argument.firstIndex(of: "=") {
                values.insert(String(argument[argument.index(after: equals)...]))
            } else if index + 1 < arguments.count, flagTakesValue(argument) {
                values.insert(arguments[index + 1])
            }
        }
        return values
    }

    /// How many leading operands are a known subcommand path, or nil when the
    /// call matches none - then only an `op://` reference is safe to name,
    /// because the operand after an unknown verb may be a `field=value` pair.
    static func knownVerbCount(_ verbs: [String]) -> Int? {
        for candidate in prefixes(of: verbs)
        where secretCommands.contains(candidate) || metadataCommands.contains(candidate) {
            return candidate.split(separator: " ").count
        }
        return nil
    }

    /// The first `op://` reference on the command line. Used where the
    /// subcommand path is unknown or the call is never cached: a reference is
    /// always safe to record, an arbitrary operand is not.
    static func reference(_ arguments: [String]) -> String? {
        arguments.first { $0.hasPrefix("op://") }
    }

    /// The operand the call names, after dropping its subcommand verbs: the
    /// `op://` reference for `read`, the item name or ID for `item get`.
    /// A `--vault` is folded in so two items of the same name stay apart.
    /// Returns nil for a call that names nothing, such as `op vault list`.
    static func subject(_ arguments: [String], verbCount: Int) -> String? {
        var operands: [String] = []
        var vault: String?
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument.hasPrefix("-") {
                if let value = inlineValue(of: argument, named: "--vault") {
                    vault = value
                } else if argument == "--vault", index + 1 < arguments.count {
                    vault = arguments[index + 1]
                }
                if !argument.contains("="), index + 1 < arguments.count, flagTakesValue(argument) {
                    index += 1
                }
                index += 1
                continue
            }
            operands.append(argument)
            index += 1
        }

        guard operands.count > verbCount else { return nil }
        let operand = operands[verbCount]
        if operand.isEmpty { return nil }
        // A share link addresses an item too, and carries its access key in
        // the fragment. The log gets the subcommand, not the link.
        if operand.lowercased().hasPrefix("http://") || operand.lowercased().hasPrefix("https://") {
            return nil
        }
        // A flag value that reached the operands through some parsing gap is
        // still a flag value. `--session TOKEN` must never come out as a subject.
        if flagValues(arguments).contains(operand) { return nil }
        if operand.hasPrefix("op://") { return operand }
        // `read` takes references only, and the listings take nothing at all.
        // Anything else there is a mistake, and a mistyped command line is the
        // one most likely to carry something meant for another program.
        if operands.first == "read" { return nil }
        if operandlessCommands.contains(operands.prefix(verbCount).joined(separator: " ")) {
            return nil
        }
        // `user get --me` names the caller; an operand beside it is a mistake.
        if arguments.contains("--me") { return nil }
        // `field=value` is an assignment, and its right-hand side is a secret
        // being written. Never recorded, whatever position it appears in -
        // including as the value of `--vault`, where op would reject it but
        // the log would not.
        if operand.contains("=") { return nil }
        guard let vault, !vault.isEmpty else { return operand }
        if vault.contains("=") { return nil }
        return "\(vault)/\(operand)"
    }

    private static func inlineValue(of argument: String, named flag: String) -> String? {
        let prefix = flag + "="
        guard argument.hasPrefix(prefix) else { return nil }
        return String(argument.dropFirst(prefix.count))
    }

    private static func prefixes(of verbs: [String]) -> [String] {
        stride(from: verbs.count, through: 1, by: -1).map {
            verbs.prefix($0).joined(separator: " ")
        }
    }

    /// Hash of the exact argument vector. Deliberately not normalised: two
    /// spellings of the same call simply miss the cache, which costs one
    /// approval, whereas collapsing them wrongly would return the wrong secret.
    /// Arguments hold references and item names, never values, so the digest
    /// carries no secret material.
    public static func cacheKey(_ arguments: [String]) -> String {
        let joined = arguments.joined(separator: "\u{0}")
        let digest = SHA256.hash(data: Data(joined.utf8))
        return "c" + digest.map { String(format: "%02x", $0) }.joined()
    }
}
