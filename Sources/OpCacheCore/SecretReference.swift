import Foundation

/// A parsed `op://vault/item[/section]/field` reference.
///
/// Everlast fork only. The proxy's primary cache is keyed by a digest of the
/// exact argument vector, which means the same secret reached two ways costs
/// two approvals. Parsing the reference is what lets a prefetched item answer
/// a call no matter how it was spelled.
///
/// Each component is kept verbatim. `vault` and `item` may be a title or an
/// ID; deciding which is the index's job, not the parser's.
public struct SecretReference: Equatable, Sendable {
    public let vault: String
    public let item: String
    /// Present only for `op://vault/item/section/field`. 1Password writes the
    /// section into the canonical reference when a field lives in one.
    public let section: String?
    public let field: String

    public init(vault: String, item: String, section: String? = nil, field: String) {
        self.vault = vault
        self.item = item
        self.section = section
        self.field = field
    }

    /// Characters 1Password accepts inside a reference segment.
    ///
    /// Measured against `op` one character at a time: letters, digits, space,
    /// underscore, hyphen, dot, and equals pass; everything else, including
    /// brackets, pipes, commas and every umlaut, fails the reference parser
    /// before any lookup happens.
    ///
    /// This is not pedantry. Without it the cache answers references that
    /// `op` refuses - measured on this machine: 32 of 240 sampled calls came
    /// back with a value from cache and an error from `op`, for items named
    /// "[CLI] N8N API Key | Ajdamirova" and the like. A cache that succeeds
    /// where the real tool fails hides the breakage until someone runs the
    /// same script without it.
    private static let allowedSegmentCharacters = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.="
    )

    /// Returns nil for anything this cache must not interpret. A reference it
    /// cannot parse is not an error: the call simply goes to `op` unchanged.
    public static func parse(_ text: String) -> SecretReference? {
        let prefix = "op://"
        guard text.hasPrefix(prefix) else { return nil }
        let body = String(text.dropFirst(prefix.count))
        guard !body.contains("\u{0}") else { return nil }

        let parts = body.components(separatedBy: "/")
        guard parts.allSatisfy({ !$0.isEmpty }) else { return nil }
        guard parts.allSatisfy({ $0.unicodeScalars.allSatisfy(allowedSegmentCharacters.contains) })
        else { return nil }

        switch parts.count {
        case 3:
            return SecretReference(vault: parts[0], item: parts[1], field: parts[2])
        case 4:
            return SecretReference(vault: parts[0], item: parts[1], section: parts[2], field: parts[3])
        default:
            // Two components addresses a whole item, five or more is not a
            // shape 1Password defines. Neither is ours to answer.
            return nil
        }
    }

    /// The part after the item, which is what a field's own canonical
    /// reference carries: "credential" or "Section/Field".
    public var fieldPath: String {
        guard let section else { return field }
        return "\(section)/\(field)"
    }
}
