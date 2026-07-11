import AppKit
import Foundation
import OpCacheCore

enum Watcher {
    @MainActor
    static func run(includeScreenLock: Bool) -> Never {
        log("Watching for system sleep\(includeScreenLock ? " and screen lock" : ""); will clear every cached profile on each event.")

        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: nil
        ) { _ in clearAll(trigger: "system sleep") }

        if includeScreenLock {
            DistributedNotificationCenter.default().addObserver(
                forName: Notification.Name("com.apple.screenIsLocked"),
                object: nil,
                queue: nil
            ) { _ in clearAll(trigger: "screen lock") }
        }

        // Keep-alive source so the run loop never runs dry between events.
        Timer.scheduledTimer(withTimeInterval: 86_400, repeats: true) { _ in }
        while true {
            RunLoop.current.run(mode: .default, before: .distantFuture)
        }
    }

    // Enumerates profiles from the Keychain itself, not the config: clearing
    // must not fail open when the config is missing or unreadable, and must
    // also reach profiles that were removed from the config.
    private static func clearAll(trigger: String) {
        do {
            let keychain = KeychainStore()
            let profiles = try keychain.allProfiles()
            for profile in profiles {
                try keychain.clear(profile: profile)
            }
            log(profiles.isEmpty
                ? "Nothing cached to clear on \(trigger)."
                : "Cleared \(profiles.joined(separator: ", ")) on \(trigger).")
        } catch {
            log("ERROR: could not clear cache on \(trigger): \(error.localizedDescription)")
        }
    }

    private static func log(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("[\(timestamp)] \(message)")
        fflush(stdout)
    }
}
