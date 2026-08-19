import Foundation

/// A prefetched item, decoded far enough to answer the calls this cache serves.
///
/// Everlast fork only. Only the shapes that were measured against the real
/// `op` are modelled here. Anything else returns nil and the call goes to
/// `op`, because a cache that guesses a format returns a wrong answer instead
/// of an approval prompt.
public struct ItemPayload: Sendable {
    public struct Section: Decodable, Sendable {
        public let id: String?
        public let label: String?
    }

    public struct Field: Decodable, Sendable {
        public let id: String?
        public let label: String?
        public let type: String?
        public let purpose: String?
        public let value: String?
        public let section: Section?

        /// 1Password prints this instead of the value when a concealed field
        /// is read without `--reveal`. Measured: the item ID appears here even
        /// when the caller addressed the item by title.
        public var isConcealed: Bool { type == "CONCEALED" }
    }

    public let id: String
    public let title: String
    public let fields: [Field]
    /// Every `href` on the item. `op` resolves an item by these too, which is
    /// why the index has to know them.
    public let urls: [String]
    /// The verbatim stdout that produced this payload, replayed as-is for
    /// `--format json` so no re-encoding can drift from 1Password's output.
    public let rawJSON: String

    private struct URLWire: Decodable {
        let href: String?
    }

    private struct Wire: Decodable {
        let id: String
        let title: String
        let fields: [Field]?
        let urls: [URLWire]?
    }

    public static func decode(_ json: String) -> ItemPayload? {
        guard let data = json.data(using: .utf8),
              let wire = try? JSONDecoder().decode(Wire.self, from: data) else { return nil }
        return ItemPayload(
            id: wire.id,
            title: wire.title,
            fields: wire.fields ?? [],
            urls: (wire.urls ?? []).compactMap(\.href),
            rawJSON: json
        )
    }

    // MARK: - Field lookup

    /// Fields a name could mean. Measured against `op`: a field is reachable
    /// by its ID or its label, and the match is case-insensitive on both.
    ///
    /// More than one candidate is not resolved here. `op` would have to pick
    /// too, and picking differently would hand back the wrong secret, so the
    /// caller forwards those calls instead.
    public func candidates(for name: String, section: String? = nil) -> [Field] {
        fields.filter { field in
            guard matches(section: section, in: field) else { return false }
            return equal(field.id, name) || equal(field.label, name)
        }
    }

    /// Exactly one field or nothing.
    public func field(named name: String, section: String? = nil) -> Field? {
        let found = candidates(for: name, section: section)
        return found.count == 1 ? found[0] : nil
    }

    private func matches(section: String?, in field: Field) -> Bool {
        guard let section else { return true }
        return equal(field.section?.id, section) || equal(field.section?.label, section)
    }

    private func equal(_ lhs: String?, _ rhs: String) -> Bool {
        guard let lhs else { return false }
        return lhs.caseInsensitiveCompare(rhs) == .orderedSame
    }

    // MARK: - Rendering

    /// `op read` output: the bare value, with a trailing newline unless
    /// `--no-newline` was given. A field that exists but holds no value prints
    /// as an empty line, which is why a missing `value` is "" and not nil.
    ///
    /// The newline is added only when the value does not already end in one.
    /// Measured on a notes field ending in two blank lines: `op` printed 754
    /// bytes where an unconditional append produced 755.
    public func renderRead(field: Field, noNewline: Bool) -> String {
        let value = field.value ?? ""
        if noNewline || value.hasSuffix("\n") { return value }
        return value + "\n"
    }

    /// `op item get --fields` output: one CSV record.
    ///
    /// Without `--reveal`, concealed fields print a fixed hint that always
    /// names the item ID, never the spelling the caller used. Verified against
    /// `op` for both addressing styles.
    public func renderFields(_ found: [Field], reveal: Bool) -> String {
        let cells = found.map { field -> String in
            if field.isConcealed, !reveal {
                return "[use 'op item get \(id) --reveal' to reveal]"
            }
            return field.value ?? ""
        }
        return CSVRecord.encode(cells) + "\n"
    }
}

/// The comma-separated record `op item get --fields` writes.
///
/// 1Password is a Go program and its output matches Go's encoding/csv: a cell
/// is quoted when it holds a comma, a quote, or a line break, or when it
/// starts with a space or tab; inner quotes are doubled. Values that need no
/// quoting are written bare, which is what makes the single-field case look
/// like a plain value.
public enum CSVRecord {
    public static func encode(_ cells: [String]) -> String {
        cells.map(encodeCell).joined(separator: ",")
    }

    public static func needsQuoting(_ cell: String) -> Bool {
        if cell.isEmpty { return false }
        if cell == #"\."# { return true }
        if cell.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) { return true }
        let first = cell.first!
        return first == " " || first == "\t"
    }

    private static func encodeCell(_ cell: String) -> String {
        guard needsQuoting(cell) else { return cell }
        return "\"" + cell.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
