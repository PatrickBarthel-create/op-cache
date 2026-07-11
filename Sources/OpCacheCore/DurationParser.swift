import Foundation

public enum DurationParser {
    public static func parse(_ input: String) throws -> TimeInterval {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let pattern = #"^([1-9][0-9]*)(s|m|h|d)$"#
        let regex = try NSRegularExpression(pattern: pattern)
        let range = NSRange(value.startIndex..., in: value)

        guard let match = regex.firstMatch(in: value, range: range),
              let numberRange = Range(match.range(at: 1), in: value),
              let unitRange = Range(match.range(at: 2), in: value),
              let number = TimeInterval(value[numberRange]) else {
            throw OpCacheError.message("Invalid TTL '\(input)'. Use values such as 30m, 1h, or 1d.")
        }

        let multiplier: TimeInterval = switch value[unitRange] {
        case "s": 1
        case "m": 60
        case "h": 3_600
        case "d": 86_400
        default: 0
        }

        let duration = number * multiplier
        guard duration <= 86_400 else {
            throw OpCacheError.message("TTL must not exceed 1d.")
        }
        return duration
    }
}
