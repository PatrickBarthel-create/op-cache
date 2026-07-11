import Foundation
import OpCacheCore

func loadAppConfig() throws -> AppConfig {
    let override = ProcessInfo.processInfo.environment["OP_CACHE_CONFIG"].map {
        URL(fileURLWithPath: NSString(string: $0).expandingTildeInPath)
    }
    return try ConfigLoader.load(from: override)
}
