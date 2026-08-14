import Foundation

/// On-disk cache for `op` output that contains no secret field values:
/// item listings, vault listings, account and user metadata.
///
/// Everlast fork only. Two deliberate differences from the Keychain store:
///
///  - **No expiry.** Metadata is not secret material, and a stale listing is a
///    correctness problem rather than a security one. It is invalidated on the
///    two events that can actually make it wrong: any mutating `op` call, and a
///    lookup that fails to find an item.
///  - **Files, not the Keychain.** A full `op item list --format json` runs to
///    megabytes, which the Keychain handles badly.
public struct MetaCache: Sendable {
    /// Entries above this size are served from `op` every time rather than
    /// filling the disk cache.
    public static let maximumEntryBytes = 8 * 1024 * 1024

    private let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory ?? MetaCache.defaultDirectory()
    }

    public static func defaultDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Caches/op-cache/meta")
    }

    public func get(key: String) -> String? {
        let url = directory.appendingPathComponent(key)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else {
            return nil
        }
        // Refuse anything another user could have written.
        if let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value != getuid() {
            return nil
        }
        if let permissions = attributes[.posixPermissions] as? NSNumber,
           permissions.uint16Value & 0o077 != 0 {
            return nil
        }
        guard let data = try? Data(contentsOf: url) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    public func put(key: String, value: String) throws {
        let data = Data(value.utf8)
        guard data.count <= MetaCache.maximumEntryBytes else { return }

        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let url = directory.appendingPathComponent(key)
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Drops every cached listing. Called after mutating commands and whenever
    /// a lookup misses, so a newly created item is visible on the next call.
    @discardableResult
    public func clear() -> Int {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            return 0
        }
        var removed = 0
        for name in names {
            let url = directory.appendingPathComponent(name)
            if (try? FileManager.default.removeItem(at: url)) != nil { removed += 1 }
        }
        return removed
    }

    public func count() -> Int {
        (try? FileManager.default.contentsOfDirectory(atPath: directory.path))?.count ?? 0
    }

    /// Whether `op` failed because it could not find what was asked for.
    /// Those failures are the signal that a cached listing has gone stale.
    public static func indicatesStaleLookup(_ stderrText: String) -> Bool {
        let text = stderrText.lowercased()
        let markers = [
            "isn't an item",
            "isn't a vault",
            "no item matches",
            "not found",
            "doesn't exist",
            "more than one item matches",
        ]
        return markers.contains { text.contains($0) }
    }
}
