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

sweep removes expired, changed, or no-longer-allowlisted entries in all profiles.
watch runs until stopped and clears all profiles on system sleep; --lock also
clears on screen lock. Install it as a LaunchAgent with 'make install-watch'.

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

        print("Authenticate 1Password once to unlock '\(profileName)' for \(ttlText).")
        try onePassword.authenticate(account: profile.account)

        var fetched: [String: String] = [:]
        for name in profile.secrets.keys.sorted() {
            guard let reference = profile.secrets[name] else { continue }
            fetched[name] = try onePassword.read(reference: reference, account: profile.account)
        }

        let now = Date()
        let expiresAt = now.addingTimeInterval(ttl)
        let keychain = KeychainStore()
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

    private static func loadConfig() throws -> AppConfig {
        try loadAppConfig()
    }

    private static func format(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .standard)
    }
}
