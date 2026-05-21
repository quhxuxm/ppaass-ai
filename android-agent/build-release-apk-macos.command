#!/bin/bash
set -euo pipefail

# Build the Android release APK on macOS.
# Run this script from any directory; output goes to app/build/outputs/apk/release.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -z "${ANDROID_HOME:-}" ] && [ -d "$HOME/Library/Android/sdk" ]; then
  export ANDROID_HOME="$HOME/Library/Android/sdk"
fi

if [ -z "${ANDROID_HOME:-}" ]; then
  echo "Error: ANDROID_HOME is not set and $HOME/Library/Android/sdk was not found."
  exit 1
fi

export ANDROID_SDK_ROOT="$ANDROID_HOME"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo was not found in PATH."
  exit 1
fi

if ! cargo ndk --version >/dev/null 2>&1; then
  echo "Error: cargo-ndk was not found. Install it with: cargo install cargo-ndk"
  exit 1
fi

GRADLE_CMD=()
if [ -f "./gradlew" ]; then
  chmod +x ./gradlew || true
  GRADLE_CMD=("./gradlew")
elif command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD=("$(command -v gradle)")
else
  GRADLE_CACHE="$HOME/.gradle/wrapper/dists"
  if [ -d "$GRADLE_CACHE" ]; then
    GRADLE_BIN="$(find "$GRADLE_CACHE" -type f -path "*/bin/gradle" 2>/dev/null | sort -r | head -n 1 || true)"
    if [ -n "${GRADLE_BIN:-}" ]; then
      chmod +x "$GRADLE_BIN" || true
      GRADLE_CMD=("$GRADLE_BIN")
    fi
  fi
fi

if [ "${#GRADLE_CMD[@]}" -eq 0 ]; then
  echo "Error: Gradle was not found. Install Gradle, add it to PATH, or add a Gradle wrapper."
  exit 1
fi

echo "Using Android SDK: $ANDROID_HOME"
echo "Using Gradle: ${GRADLE_CMD[*]}"
echo "Building Android release APK..."

"${GRADLE_CMD[@]}" assembleRelease

echo
echo "Release APK output:"
find app/build/outputs/apk/release -name "*.apk" -print
