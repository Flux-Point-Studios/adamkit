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
        // Reference host adapters for partner apps (Gero). Build-verified so they
        // stay correct against the SDK, but NOT a product — partners copy these
        // files in and conform their wallet to GeroWalletBridge.
        .target(
            name: "GeroExample",
            dependencies: ["AdamKit"],
            path: "Examples/Gero",
            exclude: ["README.md"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "AdamKitTests",
            dependencies: ["AdamKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
