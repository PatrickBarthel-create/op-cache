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

    public init(kind: CallKind, key: String?, subcommand: String) {
        self.kind = kind
        self.key = key
        self.subcommand = subcommand
    }
}

public enum ProxyClassifier {
    /// Flags that make an otherwise cacheable call uncacheable, regardless of
    /// subcommand.
    private static let neverCacheFlags: Set<String> = [
        "--otp",           // time-based, a cached value is wrong within 30s
        "--session",       // caller manages its own session
        "--watch",         // streams
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
        let verbs = leadingVerbs(arguments)
        let subcommand = verbs.joined(separator: " ")

        // Global help/version never reach the network and never prompt.
        if arguments.isEmpty || arguments.contains("--help") || arguments.contains("-h")
            || arguments.contains("--version") {
            return ClassifiedCall(kind: .passthrough, key: nil, subcommand: subcommand)
        }

        if verbs.contains(where: { mutatingVerbs.contains($0) }) {
            return ClassifiedCall(kind: .mutating, key: nil, subcommand: subcommand)
        }

        if let first = verbs.first, passthroughCommands.contains(first) {
            return ClassifiedCall(kind: .passthrough, key: nil, subcommand: subcommand)
        }

        if arguments.contains(where: { neverCacheFlags.contains($0) }) {
            return ClassifiedCall(kind: .passthrough, key: nil, subcommand: subcommand)
        }

        // Longest match first so "item template list" wins over "item".
        for candidate in prefixes(of: verbs) where secretCommands.contains(candidate) {
            return ClassifiedCall(kind: .secret, key: cacheKey(arguments), subcommand: candidate)
        }
        for candidate in prefixes(of: verbs) where metadataCommands.contains(candidate) {
            return ClassifiedCall(kind: .metadata, key: cacheKey(arguments), subcommand: candidate)
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
            verbs.append(argument)
            index += 1
        }
        return verbs
    }

    private static func flagTakesValue(_ flag: String) -> Bool {
        [
            "--account", "--vault", "--fields", "--format", "--session",
            "--cache-key", "--config", "--iso-timestamps", "--encoding",
            "--out-file", "--file-mode", "--categories", "--tags", "--include-archive",
        ].contains(flag)
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
