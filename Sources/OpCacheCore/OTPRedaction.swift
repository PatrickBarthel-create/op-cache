import Foundation

/// Strips one-time-password material before an item is stored.
///
/// Everlast fork only. `op item get --format json` returns two things for an
/// OTP field: `totp`, the six digits valid for the current 30 seconds, and
/// `value`, which is the seed itself. Measured on this machine: 33 items carry
/// an OTP field and 32 of them carry the seed, among them GitHub, Cloudflare,
/// Supabase, Hetzner and Microsoft.
///
/// Caching the seed would put the second factor next to the password for the
/// whole TTL, which is the one thing a second factor exists to prevent. The
/// field itself stays in the document so the resolver can still see its type
/// and refuse to answer for it; only the secret material goes.
public enum OTPRedaction {
    /// The redacted document, or nil when it cannot be produced - in which
    /// case the caller must not store the item at all.
    public static func redact(_ json: String) -> String? {
        guard let data = json.data(using: .utf8),
              var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        guard var fields = object["fields"] as? [[String: Any]] else { return json }

        var changed = false
        for index in fields.indices where (fields[index]["type"] as? String) == "OTP" {
            if fields[index].removeValue(forKey: "value") != nil { changed = true }
            if fields[index].removeValue(forKey: "totp") != nil { changed = true }
        }
        guard changed else { return json }

        object["fields"] = fields
        guard let encoded = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(decoding: encoded, as: UTF8.self)
    }

    /// Whether a stored document holds an OTP field at all.
    ///
    /// Two different reasons to refuse it, one test: an unredacted document
    /// carries a code that is wrong within 30 seconds, and a redacted one is
    /// no longer byte-identical to what `op` would print.
    public static func containsOTPField(_ payload: ItemPayload) -> Bool {
        payload.fields.contains { $0.type == "OTP" }
    }
}
