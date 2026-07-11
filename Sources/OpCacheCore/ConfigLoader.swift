import Foundation
import Darwin

public enum ConfigLoader {
    public static func defaultURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/op-cache/config.json")
    }

    public static func load(from url: URL? = nil) throws -> AppConfig {
        let configURL = url ?? defaultURL()
        guard FileManager.default.fileExists(atPath: configURL.path) else {
            throw OpCacheError.message("Config not found at \(configURL.path).")
        }

        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: configURL.path)
            if let owner = attributes[.ownerAccountID] as? NSNumber,
               owner.uint32Value != getuid() {
                throw OpCacheError.message("Config must be owned by the current user.")
            }
            if let permissions = attributes[.posixPermissions] as? NSNumber,
               permissions.uint16Value & 0o077 != 0 {
                throw OpCacheError.message("Config permissions must be 0600 or stricter.")
            }
            let data = try Data(contentsOf: configURL)
            return try JSONDecoder().decode(AppConfig.self, from: data)
        } catch let error as OpCacheError {
            throw error
        } catch {
            throw OpCacheError.message("Could not load config: \(error.localizedDescription)")
        }
    }
}
