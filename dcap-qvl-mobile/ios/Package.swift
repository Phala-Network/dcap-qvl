// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "DcapQvl",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(
            name: "DcapQvl",
            targets: ["DcapQvl"]
        ),
    ],
    targets: [
        // The Rust-generated XCFramework. Built by `scripts/build_ios.sh`
        // into `ios/DcapQvlFFI.xcframework`.
        .binaryTarget(
            name: "DcapQvlFFI",
            path: "DcapQvlFFI.xcframework"
        ),
        // The Swift wrapper (UniFFI-generated glue + the hand-written facade).
        .target(
            name: "DcapQvl",
            dependencies: ["DcapQvlFFI"],
            path: "Sources/DcapQvl"
        ),
        .testTarget(
            name: "DcapQvlTests",
            dependencies: ["DcapQvl"],
            path: "Tests/DcapQvlTests",
            resources: [
                .copy("Resources/sgx_quote"),
                .copy("Resources/sgx_quote_collateral.json"),
                .copy("Resources/tdx_quote"),
                .copy("Resources/tdx_quote_collateral.json"),
            ]
        ),
    ]
)
