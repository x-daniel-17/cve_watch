// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "CVEWatchGUI",
    platforms: [.macOS("26.0")],
    targets: [
        .executableTarget(
            name: "CVEWatchGUI",
            path: "Sources",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        )
    ]
)
