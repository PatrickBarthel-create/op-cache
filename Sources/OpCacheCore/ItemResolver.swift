import Foundation

/// Answers an `op` call from prefetched items, or declines.
///
/// Everlast fork only. This is the half of the prefetch that pays off: it
/// turns one stored copy of an item into an answer for however the caller
/// spelled the request. Every step is allowed to give up, and giving up costs
/// exactly what the tool cost before — one approval.
public struct ItemResolver: Sendable {
    private let loadItem: @Sendable (ItemCoordinate) -> String?
    private let loadIndex: @Sendable () -> ItemIndex?

    public init(
        store: ItemStore = ItemStore(),
        loadIndex: @escaping @Sendable () -> ItemIndex? = { ItemIndex.load() }
    ) {
        self.init(loadItem: { store.get($0) }, loadIndex: loadIndex)
    }

    /// Both sources injected, which is how the render rules are tested without
    /// a Keychain or a real 1Password account.
    public init(
        loadItem: @escaping @Sendable (ItemCoordinate) -> String?,
        loadIndex: @escaping @Sendable () -> ItemIndex?
    ) {
        self.loadItem = loadItem
        self.loadIndex = loadIndex
    }

    /// The exact bytes `op` would have written to stdout, or nil.
    public func answer(for arguments: [String]) -> String? {
        guard let call = SecretCall.parse(arguments),
              let index = loadIndex() else { return nil }

        let coordinates: [ItemCoordinate]
        switch call {
        case let .read(reference, account, _):
            coordinates = index.resolve(reference, accountHint: account)
        case let .itemJSON(item, vault, account):
            coordinates = index.resolveItem(item, vaultHint: vault, accountHint: account)
        case let .itemFields(item, vault, account, _, _):
            coordinates = index.resolveItem(item, vaultHint: vault, accountHint: account)
        }

        // Two matches is what `op` reports as "more than one item matches".
        // Answering either one would replace that error with a wrong secret.
        guard coordinates.count == 1,
              let json = loadItem(coordinates[0]),
              let payload = ItemPayload.decode(json) else { return nil }

        switch call {
        case let .read(reference, _, noNewline):
            guard let field = payload.field(named: reference.field, section: reference.section),
                  field.type != "OTP" else { return nil }
            return payload.renderRead(field: field, noNewline: noNewline)

        case .itemJSON:
            // The whole document is off limits once it holds an OTP field:
            // unredacted it carries a code that expires in 30 seconds,
            // redacted it no longer matches what `op` prints.
            guard !OTPRedaction.containsOTPField(payload) else { return nil }
            return payload.rawJSON

        case let .itemFields(_, _, _, specs, reveal):
            var found: [ItemPayload.Field] = []
            for spec in specs {
                guard let name = fieldName(from: spec),
                      let field = payload.field(named: name),
                      field.type != "OTP" else { return nil }
                found.append(field)
            }
            return payload.renderFields(found, reveal: reveal)
        }
    }

    /// `--fields` accepts a bare name or `label=<name>`; measured, `label=`
    /// matches a field's ID just as a bare name does. `id=` is not a selector
    /// `op` understands, and other prefixes were never measured, so both give
    /// up rather than guess.
    private func fieldName(from spec: String) -> String? {
        let trimmed = spec.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return nil }
        guard let separator = trimmed.firstIndex(of: "=") else { return trimmed }
        guard trimmed[..<separator] == "label" else { return nil }
        let name = String(trimmed[trimmed.index(after: separator)...])
        return name.isEmpty ? nil : name
    }
}
