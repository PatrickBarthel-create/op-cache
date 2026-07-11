import Foundation
import Security

public struct KeychainStore: Sendable {
    private let servicePrefix = "dev.peter.op-cache"

    public init() {}

    public func put(_ secret: CachedSecret, name: String, profile: String) throws {
        let data = try JSONEncoder().encode(secret)
        let query = baseQuery(name: name, profile: profile)
        let attributes: [CFString: Any] = [kSecValueData: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData] = data
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            try check(status, operation: "store")
        } else {
            try check(updateStatus, operation: "update")
        }
    }

    public func get(name: String, profile: String) throws -> CachedSecret? {
        var query = baseQuery(name: name, profile: profile)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status, operation: "read")

        guard let data = result as? Data else {
            throw OpCacheError.message("Keychain returned invalid data for '\(name)'.")
        }
        return try JSONDecoder().decode(CachedSecret.self, from: data)
    }

    public func list(profile: String) throws -> [String] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(profile: profile),
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try check(status, operation: "list")

        guard let items = result as? [[String: Any]] else {
            throw OpCacheError.message("Keychain returned invalid attributes for profile '\(profile)'.")
        }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    /// All profiles that currently have entries in the Keychain, derived from
    /// the stored service names. Independent of the config so clearing and
    /// sweeping also reach profiles that were removed from the config.
    public func allProfiles() throws -> [String] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try check(status, operation: "enumerate")

        guard let items = result as? [[String: Any]] else { return [] }
        let prefix = "\(servicePrefix)."
        let profiles = items.compactMap { item -> String? in
            guard let service = item[kSecAttrService as String] as? String,
                  service.hasPrefix(prefix) else { return nil }
            return String(service.dropFirst(prefix.count))
        }
        return Array(Set(profiles)).sorted()
    }

    public func delete(name: String, profile: String) throws {
        let status = SecItemDelete(baseQuery(name: name, profile: profile) as CFDictionary)
        if status != errSecItemNotFound {
            try check(status, operation: "delete")
        }
    }

    public func clear(profile: String) throws {
        // Delete per item: a service-wide SecItemDelete does not reliably
        // remove every match on the file-based macOS keychain.
        for name in try list(profile: profile) {
            try delete(name: name, profile: profile)
        }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(profile: profile),
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecItemNotFound {
            try check(status, operation: "clear")
        }

        let remaining = try list(profile: profile)
        guard remaining.isEmpty else {
            throw OpCacheError.message(
                "Could not clear profile '\(profile)'; still cached: \(remaining.sorted().joined(separator: ", "))."
            )
        }
    }

    private func baseQuery(name: String, profile: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(profile: profile),
            kSecAttrAccount: name,
        ]
    }

    private func service(profile: String) -> String {
        "\(servicePrefix).\(profile)"
    }

    private func check(_ status: OSStatus, operation: String) throws {
        guard status == errSecSuccess else {
            let description = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            throw OpCacheError.message("Keychain \(operation) failed: \(description)")
        }
    }
}
