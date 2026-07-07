// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AdamKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "AdamKit", targets: ["AdamKit"])
    ],
    targets: [
        .target(
            name: "AdamKit",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "AdamKitTests",
            dependencies: ["AdamKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
