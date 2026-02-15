#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

echo "Building CVE Watch GUI..."
swift build -c release 2>&1

BINARY=".build/release/CVEWatchGUI"
if [ ! -f "$BINARY" ]; then
    echo "Error: Build failed — binary not found"
    exit 1
fi

APP_DIR="$SCRIPT_DIR/build/CVE Watch.app"
CONTENTS="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES"

cp "$BINARY" "$MACOS_DIR/CVEWatchGUI"
cp "$SCRIPT_DIR/Info.plist" "$CONTENTS/Info.plist"

# Embed project root so the app can find the Python backend from anywhere
echo "$PROJECT_ROOT" > "$RESOURCES/project_root.txt"

if [ -f "$SCRIPT_DIR/AppIcon.icns" ]; then
    cp "$SCRIPT_DIR/AppIcon.icns" "$RESOURCES/AppIcon.icns"
fi

echo "✓ Built: $APP_DIR"

# Install to /Applications if requested
if [[ "${1:-}" == "--install" ]]; then
    INSTALL_DIR="/Applications/CVE Watch.app"
    echo ""
    echo "Installing to /Applications..."
    rm -rf "$INSTALL_DIR"
    cp -R "$APP_DIR" "$INSTALL_DIR"
    echo "✓ Installed to $INSTALL_DIR"
    echo ""
    echo "Open CVE Watch from Launchpad, Spotlight, or the Dock."
fi
