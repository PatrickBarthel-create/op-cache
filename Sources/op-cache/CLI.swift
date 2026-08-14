import Darwin
import Foundation
import OpCacheCore

private let usage = """
op-cache: authorize once, use allowlisted 1Password secrets for a short window

Usage:
  op-cache unlock <profile> [--ttl 8h]
  op-cache run <profile> [--only NAME,NAME] -- <command> [args...]
  op-cache status <profile>
  op-cache clear <profile>
  op-cache sweep
  op-cache watch [--lock]
  op-cache proxy -- op <args...>
  op-cache refresh

sweep removes expired, changed, or no-longer-allowlisted entries in all profiles.
watch runs until stopped and clears all profiles on system sleep; --lock also
clears on screen lock. Install it as a LaunchAgent with 'make install-watch'.

proxy answers an op invocation from cache when that is safe and forwards it
otherwise; install the shim with 'make install-shim' so plain 'op' uses it.
Set OP_CACHE_SHIM=0 to bypass it for one command. Proxied secrets live in the
'_proxy' profile; 'op-cache status _proxy' and 'op-cache clear _proxy' work on
them. refresh drops the cached listings so newly created items become visible.

Config: ~/.config/op-cache/config.json
Override with OP_CACHE_CONFIG=/path/to/config.json
"""

@main
enum CLI {
    static func main() {
        do {
            try execute(Array(CommandLine.arguments.dropFirst()))
        } catch {
            fputs("op-cache: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    private static func execute(_ arguments: [String]) throws {
        guard let command = arguments.first else {
            print(usage)
            return
        }

        switch command {
        case "help", "--help", "-h":
            print(usage)
        case "unlock":
            try unlock(Array(arguments.dropFirst()))
        case "run":
            try run(Array(arguments.dropFirst()))
        case "status":
            try status(Array(arguments.dropFirst()))
        case "clear":
            try clear(Array(arguments.dropFirst()))
        case "sweep":
            try sweep()
        case "watch":
            try watch(Array(arguments.dropFirst()))
        case "proxy":
            try proxy(Array(arguments.dropFirst()))
        case "refresh":
            refresh()
        default:
            throw OpCacheError.message("Unknown command '\(command)'.\n\n\(usage)")
        }
    }

    private static func unlock(_ arguments: [String]) throws {
        let parsed = try CLIArgumentParser.parseUnlock(arguments)
        let profileName = parsed.profile

        let config = try loadConfig()
        let profile = try config.profile(named: profileName)
        let ttlText = parsed.ttl ?? profile.ttl ?? config.defaultTTL ?? "8h"
        let ttl = try DurationParser.parse(ttlText)
        let onePassword = OnePassword()
        let keychain = KeychainStore()

        // Everlast fork only: fetch what is missing rather than the whole
        // profile. Upstream refetches every secret on each unlock, which turns
        // adding one entry into a full re-read of the profile.
        var missing: [String] = []
        for name in profile.secrets.keys.sorted() {
            guard let reference = profile.secrets[name] else { continue }
            let cached = try? keychain.get(name: name, profile: profileName)
            if cached?.isValid(reference: reference, account: profile.account) != true {
                missing.append(name)
            }
        }

        guard !missing.isEmpty else {
            print("'\(profileName)' is already unlocked; nothing to fetch.")
            return
        }

        print("Authenticate 1Password once to unlock '\(profileName)' for \(ttlText).")
        try onePassword.authenticate(account: profile.account)

        var fetched: [String: String] = [:]
        for name in missing {
            guard let reference = profile.secrets[name] else { continue }
            fetched[name] = try onePassword.read(reference: reference, account: profile.account)
        }

        let now = Date()
        let expiresAt = now.addingTimeInterval(ttl)
        for name in fetched.keys.sorted() {
            guard let value = fetched[name], let reference = profile.secrets[name] else { continue }
            let cached = CachedSecret(
                reference: reference,
                account: profile.account,
                value: value,
                fetchedAt: now,
                expiresAt: expiresAt
            )
            try keychain.put(cached, name: name, profile: profileName)
        }

        AuditLog(config: config.audit).record(
            AuditEvent(
                timestamp: now,
                event: .unlock,
                profile: profileName,
                account: profile.account,
                secrets: auditSecrets(names: fetched.keys, profile: profile),
                ttl: ttlText,
                expiresAt: expiresAt
            )
        )

        print("Unlocked \(fetched.count) allowlisted secret(s) until \(format(expiresAt)).")
    }

    private static func run(_ arguments: [String]) throws {
        let parsed = try CLIArgumentParser.parseRun(arguments)
        let profileName = parsed.profile

        let config = try loadConfig()
        let profile = try config.profile(named: profileName)
        let selectedNames = try selectedSecretNames(requested: parsed.only, profile: profile)
        let keychain = KeychainStore()
        var injected: [String: String] = [:]
        var unavailable: [String] = []

        for name in selectedNames.sorted() {
            guard let reference = profile.secrets[name] else { continue }
            guard let cached = try keychain.get(name: name, profile: profileName),
                  cached.isValid(reference: reference, account: profile.account) else {
                try keychain.delete(name: name, profile: profileName)
                unavailable.append(name)
                continue
            }
            injected[name] = cached.value
        }

        guard unavailable.isEmpty else {
            throw OpCacheError.message(
                "Cache is locked, expired, or changed for: \(unavailable.sorted().joined(separator: ", ")). " +
                "Run 'op-cache unlock \(profileName)'."
            )
        }

        // Recorded before the spawn: the injection is what happens here, and
        // this process exits with the child's status without returning.
        AuditLog(config: config.audit).record(
            AuditEvent(
                event: .run,
                profile: profileName,
                account: profile.account,
                secrets: auditSecrets(names: injected.keys, profile: profile),
                command: parsed.command.first,
                argumentCount: max(parsed.command.count - 1, 0)
            )
        )

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = parsed.command
        let configuredNames = config.profiles.values.flatMap(\.secrets.keys)
        process.environment = ChildEnvironment.compose(
            base: ProcessInfo.processInfo.environment,
            removing: configuredNames,
            injecting: injected
        )
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        exit(process.terminationStatus)
    }

    private static func status(_ arguments: [String]) throws {
        guard let profileName = arguments.first else {
            throw OpCacheError.message("Usage: op-cache status <profile>")
        }
        if profileName == ProxyRunner.profileName {
            try proxyStatus()
            return
        }
        let profile = try loadConfig().profile(named: profileName)
        let keychain = KeychainStore()

        for name in profile.secrets.keys.sorted() {
            guard let reference = profile.secrets[name],
                  let cached = try keychain.get(name: name, profile: profileName) else {
                print("\(name): locked")
                continue
            }
            if cached.isValid(reference: reference, account: profile.account) {
                print("\(name): unlocked until \(format(cached.expiresAt))")
            } else {
                try keychain.delete(name: name, profile: profileName)
                print("\(name): expired")
            }
        }
    }

    /// The proxy profile is keyed by a digest of the command line, so listing
    /// entry names would say nothing. What is useful is how much is open and
    /// for how long.
    private static func proxyStatus() throws {
        let keychain = KeychainStore()
        let names = try keychain.list(profile: ProxyRunner.profileName)
        var live = 0
        var expired = 0
        var latest: Date?

        for name in names {
            guard let cached = try keychain.get(name: name, profile: ProxyRunner.profileName),
                  cached.isValid(reference: name, account: ProxyRunner.profileName) else {
                expired += 1
                continue
            }
            live += 1
            if latest == nil || cached.expiresAt > latest! { latest = cached.expiresAt }
        }

        print("proxied secrets: \(live) unlocked, \(expired) expired")
        if let latest {
            print("last one expires \(format(latest))")
        }
        print("cached listings: \(MetaCache().count()) (no expiry; 'op-cache refresh' drops them)")
    }

    private static func clear(_ arguments: [String]) throws {
        guard let profileName = arguments.first else {
            throw OpCacheError.message("Usage: op-cache clear <profile>")
        }
        // Deliberately config-free so profiles removed from the config can
        // still be cleared.
        try KeychainStore().clear(profile: profileName)
        print("Cleared profile '\(profileName)'.")
    }

    private static func sweep() throws {
        let config = try loadConfig()
        let keychain = KeychainStore()
        var removed = 0

        for profileName in try keychain.allProfiles() {
            // The proxy profile is populated at call time and never appears in
            // the config, so the "not in config" rule would wipe it wholesale.
            // Its entries still age out like any other.
            if profileName == ProxyRunner.profileName {
                for name in try keychain.list(profile: profileName).sorted() {
                    guard let cached = try keychain.get(name: name, profile: profileName),
                          cached.isValid(reference: name, account: profileName) else {
                        try keychain.delete(name: name, profile: profileName)
                        removed += 1
                        continue
                    }
                }
                continue
            }
            guard let profile = config.profiles[profileName] else {
                removed += try keychain.list(profile: profileName).count
                try keychain.clear(profile: profileName)
                print("\(profileName): removed (profile no longer in config)")
                continue
            }
            try profile.validate()
            for name in try keychain.list(profile: profileName).sorted() {
                guard let reference = profile.secrets[name] else {
                    try keychain.delete(name: name, profile: profileName)
                    removed += 1
                    print("\(profileName)/\(name): removed (no longer allowlisted)")
                    continue
                }
                guard let cached = try keychain.get(name: name, profile: profileName),
                      cached.isValid(reference: reference, account: profile.account) else {
                    try keychain.delete(name: name, profile: profileName)
                    removed += 1
                    print("\(profileName)/\(name): removed (expired, changed, or account mismatch)")
                    continue
                }
            }
        }

        print(removed == 0 ? "Nothing to sweep." : "Removed \(removed) stale entr\(removed == 1 ? "y" : "ies").")
    }

    private static func watch(_ arguments: [String]) throws {
        var includeScreenLock = false
        for argument in arguments {
            switch argument {
            case "--lock":
                includeScreenLock = true
            default:
                throw OpCacheError.message("Unknown watch option '\(argument)'. Usage: op-cache watch [--lock]")
            }
        }
        MainActor.assumeIsolated {
            Watcher.run(includeScreenLock: includeScreenLock)
        }
    }

    /// Everlast fork only. Answers one `op` invocation, from cache where that
    /// is safe.
    ///
    /// This runs in place of `op` for every call on the machine, so it must
    /// never be able to break `op`. Any failure of our own — missing config,
    /// unreadable Keychain, a classification we did not anticipate — falls
    /// through to running `op` unchanged.
    private static func proxy(_ arguments: [String]) throws {
        let separator = arguments.firstIndex(of: "--")
        let command = separator.map { Array(arguments[($0 + 1)...]) } ?? arguments
        guard !command.isEmpty else {
            throw OpCacheError.message("Usage: op-cache proxy -- op <args...>")
        }

        // The shim passes the full command line including the "op" it replaced.
        let opArguments = command.first == "op" || command.first?.hasSuffix("/op") == true
            ? Array(command.dropFirst())
            : command

        let onePassword = OnePassword()

        func forward() -> Never {
            let status = (try? onePassword.passthrough(opArguments)) ?? 1
            exit(status)
        }

        // A config is required for the TTL, but its absence must not take op
        // down with it.
        guard let config = try? loadConfig() else { forward() }
        let ttlText = config.defaultTTL ?? "8h"
        guard let ttl = try? DurationParser.parse(ttlText) else { forward() }

        let runner = ProxyRunner(
            onePassword: onePassword,
            audit: AuditLog(config: config.audit, warn: { _ in }),
            ttl: ttl,
            ttlText: ttlText
        )

        guard let status = try? runner.run(opArguments) else { forward() }
        exit(status)
    }

    /// Drops the cached listings. The metadata cache has no expiry, so this is
    /// the manual counterpart to the automatic invalidation on writes and
    /// failed lookups.
    private static func refresh() {
        let removed = MetaCache().clear()
        print(removed == 0 ? "No cached listings." : "Dropped \(removed) cached listing(s).")
    }

    private static func selectedSecretNames(
        requested: Set<String>?,
        profile: ProfileConfig
    ) throws -> Set<String> {
        guard let names = requested else {
            return Set(profile.secrets.keys)
        }
        let unknown = names.filter { profile.secrets[$0] == nil }
        guard unknown.isEmpty else {
            throw OpCacheError.message("Secrets are not allowlisted: \(unknown.sorted().joined(separator: ", ")).")
        }
        return names
    }

    private static func auditSecrets(
        names: some Sequence<String>,
        profile: ProfileConfig
    ) -> [AuditSecret] {
        names.sorted().compactMap { name in
            profile.secrets[name].map { AuditSecret(name: name, reference: $0) }
        }
    }

    private static func loadConfig() throws -> AppConfig {
        try loadAppConfig()
    }

    private static func format(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .standard)
    }
}
