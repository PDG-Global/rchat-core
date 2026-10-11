#!/bin/bash
set -e

# Quick build script for macOS development (faster than full iOS build)

echo "Building RChat Core for macOS (development)..."

# Build for macOS native
cargo build --release --target aarch64-apple-darwin

# Generate Swift bindings
echo "Generating Swift bindings..."
cargo run --bin uniffi-bindgen generate --library ./target/aarch64-apple-darwin/release/librchat_core.a --language swift --out-dir ./bindings

# Rename modulemap for XCFramework
if [ -f ./bindings/rchat_coreFFI.modulemap ]; then
    mv ./bindings/rchat_coreFFI.modulemap ./bindings/module.modulemap
fi

# Create XCFramework for macOS only
echo "Creating XCFramework..."
rm -rf RChatCore.xcframework

xcodebuild -create-xcframework \
    -library ./target/aarch64-apple-darwin/release/librchat_core.a -headers ./bindings \
    -output RChatCore.xcframework

echo ""
echo "Build complete!"
echo "XCFramework: $(pwd)/RChatCore.xcframework"
echo "Swift bindings: $(pwd)/bindings/rchat_core.swift"
