import Foundation

public struct AppConfig: Codable, Sendable {
    public var defaultTTL: String?
    public var audit: AuditConfig?
    public var profiles: [String: ProfileConfig]

    public init(
        defaultTTL: String? = nil,
        audit: AuditConfig? = nil,
        profiles: [String: ProfileConfig]
    ) {
        self.defaultTTL = defaultTTL
        self.audit = audit
        self.profiles = profiles
    }

    public func profile(named name: String) throws -> ProfileConfig {
        guard let profile = profiles[name] else {
            throw OpCacheError.message("Unknown profile '\(name)'.")
        }
        try validateIdentifier(name, kind: "profile")
        try profile.validate()
        return profile
    }
}

public struct ProfileConfig: Codable, Sendable {
    public var account: String
    public var ttl: String?
    public var secrets: [String: String]

    public init(account: String, ttl: String? = nil, secrets: [String: String]) {
        self.account = account
        self.ttl = ttl
        self.secrets = secrets
    }

    public func validate() throws {
        guard !account.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw OpCacheError.message("A profile account cannot be empty.")
        }
        guard !secrets.isEmpty else {
            throw OpCacheError.message("A profile must allowlist at least one secret.")
        }
        for (name, reference) in secrets {
            try validateIdentifier(name, kind: "environment variable")
            guard reference.hasPrefix("op://"), reference.count > 5 else {
                throw OpCacheError.message("Secret '\(name)' must use an op:// reference.")
            }
        }
    }
}

public struct CachedSecret: Codable, Sendable {
    public let reference: String
    // Optional so entries cached before account binding still decode; they
    // never validate, which forces a fresh fetch.
    public let account: String?
    public let value: String
    public let fetchedAt: Date
    public let expiresAt: Date

    public init(reference: String, account: String, value: String, fetchedAt: Date, expiresAt: Date) {
        self.reference = reference
        self.account = account
        self.value = value
        self.fetchedAt = fetchedAt
        self.expiresAt = expiresAt
    }

    public func isValid(
        reference expectedReference: String,
        account expectedAccount: String,
        at date: Date = Date()
    ) -> Bool {
        reference == expectedReference && account == expectedAccount && date < expiresAt
    }
}

public enum OpCacheError: Error, LocalizedError, Equatable {
    case message(String)

    public var errorDescription: String? {
        switch self {
        case let .message(message): message
        }
    }
}

private func validateIdentifier(_ value: String, kind: String) throws {
    let pattern = "^[A-Za-z_][A-Za-z0-9_-]*$"
    guard value.range(of: pattern, options: .regularExpression) != nil else {
        throw OpCacheError.message("Invalid \(kind) name '\(value)'.")
    }
}
