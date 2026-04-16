#!/bin/bash
set -euo pipefail

export DEVELOPER_DIR=/Applications/Xcode-26.2.0.app/Contents/Developer

SCHEME="SwiftyDropbox"
FRAMEWORK_NAME="SwiftyDropbox"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/build"
DERIVED_DIR="$BUILD_DIR/derived"
STAGING_DIR="$BUILD_DIR/staging"
OUTPUT_DIR="$BUILD_DIR/xcframeworks"

echo "Cleaning build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$DERIVED_DIR" "$STAGING_DIR" "$OUTPUT_DIR"

COMMON_FLAGS=(
    SKIP_INSTALL=NO
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES
    ONLY_ACTIVE_ARCH=NO
)

build_for() {
    local name=$1 destination=$2
    shift 2
    xcodebuild build \
        -scheme "$SCHEME" \
        -destination "$destination" \
        -configuration Release \
        -derivedDataPath "$DERIVED_DIR/$name" \
        "${COMMON_FLAGS[@]}" \
        "$@"
}

echo "Building iOS (arm64)..."
build_for ios "generic/platform=iOS"

echo "Building iOS Simulator (arm64 + x86_64)..."
build_for ios-simulator "generic/platform=iOS Simulator"

echo "Building Mac Catalyst (arm64 + x86_64)..."
build_for catalyst "generic/platform=macOS,variant=Mac Catalyst" \
    SUPPORTS_MACCATALYST=YES \
    ARCHS="arm64 x86_64"

# SPM's xcodebuild-generated projects emit the framework into PackageFrameworks/
# but place the .swiftmodule alongside it rather than inside it. Stage a copy of
# each framework with the swiftmodule moved into its Modules/ directory.
stage_framework() {
    local name=$1 products_subdir=$2
    local products="$DERIVED_DIR/$name/Build/Products/$products_subdir"
    local src_fw="$products/PackageFrameworks/$FRAMEWORK_NAME.framework"
    local src_swiftmodule="$products/$FRAMEWORK_NAME.swiftmodule"
    local dest_fw="$STAGING_DIR/$name/$FRAMEWORK_NAME.framework"

    [ -d "$src_fw" ] || { echo "Framework not found at $src_fw"; exit 1; }
    [ -d "$src_swiftmodule" ] || { echo "swiftmodule not found at $src_swiftmodule"; exit 1; }

    mkdir -p "$STAGING_DIR/$name"
    rm -rf "$dest_fw"
    cp -R "$src_fw" "$dest_fw"

    local modules_dir
    if [ -d "$dest_fw/Versions/A" ]; then
        modules_dir="$dest_fw/Versions/A/Modules"
        mkdir -p "$modules_dir"
        cp -R "$src_swiftmodule" "$modules_dir/"
        (cd "$dest_fw" && [ -L Modules ] || ln -s Versions/Current/Modules Modules)
    else
        modules_dir="$dest_fw/Modules"
        mkdir -p "$modules_dir"
        cp -R "$src_swiftmodule" "$modules_dir/"
    fi

    echo "Staged: $dest_fw"
}

stage_framework ios Release-iphoneos
stage_framework ios-simulator Release-iphonesimulator
stage_framework catalyst Release-maccatalyst

IOS_FW="$STAGING_DIR/ios/$FRAMEWORK_NAME.framework"
IOS_SIM_FW="$STAGING_DIR/ios-simulator/$FRAMEWORK_NAME.framework"
CATALYST_FW="$STAGING_DIR/catalyst/$FRAMEWORK_NAME.framework"

# Sanity check: every slice must carry its swiftmodule so consumers can import.
for fw in "$IOS_FW" "$IOS_SIM_FW" "$CATALYST_FW"; do
    modules="$fw/Modules"
    [ -d "$fw/Versions/A/Modules" ] && modules="$fw/Versions/A/Modules"
    if ! find "$modules" -name "*.swiftinterface" -print -quit | grep -q .; then
        echo "ERROR: no .swiftinterface under $modules"
        exit 1
    fi
done

echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -framework "$IOS_FW" \
    -framework "$IOS_SIM_FW" \
    -framework "$CATALYST_FW" \
    -output "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

echo "Zipping..."
cd "$OUTPUT_DIR"
zip -qr "$FRAMEWORK_NAME.xcframework.zip" "$FRAMEWORK_NAME.xcframework"

echo ""
echo "Checksum (paste this into SwiftyDropboxBinary/Package.swift):"
swift package compute-checksum "$FRAMEWORK_NAME.xcframework.zip"

echo ""
echo "Output: $OUTPUT_DIR/$FRAMEWORK_NAME.xcframework.zip"
