// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "op-cache",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "op-cache", targets: ["op-cache"]),
        .library(name: "OpCacheCore", targets: ["OpCacheCore"]),
    ],
    targets: [
        .target(
            name: "OpCacheCore",
            linkerSettings: [.linkedFramework("Security")]
        ),
        .executableTarget(
            name: "op-cache",
            dependencies: ["OpCacheCore"]
        ),
        .testTarget(
            name: "OpCacheCoreTests",
            dependencies: ["OpCacheCore"]
        ),
    ]
)
