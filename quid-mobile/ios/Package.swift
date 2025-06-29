// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "QuIDiOS",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "QuIDiOS",
            targets: ["QuIDiOS"]
        ),
        .library(
            name: "QuIDiOSC",
            targets: ["QuIDiOSC"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.0.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.6.0")
    ],
    targets: [
        .target(
            name: "QuIDiOS",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                "CryptoSwift",
                "QuIDiOSC"
            ],
            path: "Sources/QuIDiOS"
        ),
        .target(
            name: "QuIDiOSC",
            path: "Sources/QuIDiOSC",
            publicHeadersPath: "include"
        ),
        .testTarget(
            name: "QuIDiOSTests",
            dependencies: ["QuIDiOS"],
            path: "Tests/QuIDiOSTests"
        )
    ]
)