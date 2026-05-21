#!/bin/bash
set -euo pipefail

# Build the Android release APK on macOS.
# Run this script from any directory; output goes to app/build/outputs/apk/release.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Finder-launched .command files get a minimal PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.cargo/bin:$PATH"

if [ -z "${ANDROID_HOME:-}" ] && [ -d "$HOME/Library/Android/sdk" ]; then
  export ANDROID_HOME="$HOME/Library/Android/sdk"
fi

if [ -z "${ANDROID_HOME:-}" ]; then
  echo "Error: ANDROID_HOME is not set and $HOME/Library/Android/sdk was not found."
  exit 1
fi

export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/tools/bin:$ANDROID_HOME/tools:$PATH"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo was not found in PATH."
  exit 1
fi

if ! cargo ndk --version >/dev/null 2>&1; then
  echo "Error: cargo-ndk was not found. Install it with: cargo install cargo-ndk"
  exit 1
fi

find_android_build_tool() {
  local tool_name="$1"
  local tool_path

  tool_path="$(find "$ANDROID_HOME/build-tools" -type f -name "$tool_name" 2>/dev/null | sort | tail -n 1 || true)"
  if [ -z "$tool_path" ]; then
    echo "Error: Android build tool '$tool_name' was not found under $ANDROID_HOME/build-tools."
    exit 1
  fi

  echo "$tool_path"
}

ZIPALIGN="$(find_android_build_tool zipalign)"
APKSIGNER="$(find_android_build_tool apksigner)"

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

UNSIGNED_APK="app/build/outputs/apk/release/app-release-unsigned.apk"
ALIGNED_APK="app/build/outputs/apk/release/app-release-aligned.apk"
SIGNED_APK="app/build/outputs/apk/release/app-release-signed.apk"

if [ ! -f "$UNSIGNED_APK" ]; then
  echo "Error: unsigned release APK was not found at $UNSIGNED_APK"
  exit 1
fi

KEYSTORE="${PPAASS_RELEASE_KEYSTORE:-$SCRIPT_DIR/local-release.keystore}"
KEY_ALIAS="${PPAASS_RELEASE_KEY_ALIAS:-ppaass-local-release}"
STORE_PASSWORD="${PPAASS_RELEASE_STORE_PASSWORD:-ppaass-local-release}"
KEY_PASSWORD="${PPAASS_RELEASE_KEY_PASSWORD:-$STORE_PASSWORD}"

if [ ! -f "$KEYSTORE" ]; then
  if ! command -v keytool >/dev/null 2>&1; then
    echo "Error: keytool was not found in PATH."
    exit 1
  fi

  echo "Creating local signing keystore: $KEYSTORE"
  keytool -genkeypair \
    -keystore "$KEYSTORE" \
    -storepass "$STORE_PASSWORD" \
    -keypass "$KEY_PASSWORD" \
    -alias "$KEY_ALIAS" \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -dname "CN=PPAASS Local Release, OU=Development, O=PPAASS, L=Local, ST=Local, C=CN" \
    >/dev/null
fi

echo "Signing release APK..."
rm -f "$ALIGNED_APK" "$SIGNED_APK"
"$ZIPALIGN" -f -p 4 "$UNSIGNED_APK" "$ALIGNED_APK"
"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "pass:$STORE_PASSWORD" \
  --key-pass "pass:$KEY_PASSWORD" \
  --out "$SIGNED_APK" \
  "$ALIGNED_APK"
"$APKSIGNER" verify --verbose "$SIGNED_APK"
rm -f "$ALIGNED_APK"

echo
echo "Installable release APK:"
echo "$SIGNED_APK"
echo
echo "All release APK output:"
find app/build/outputs/apk/release -name "*.apk" -print
