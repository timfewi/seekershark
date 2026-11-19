#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

export PATH="$HOME/.cargo/bin:$HOME/.bun/bin:$PATH"
if [[ -z "${ANDROID_HOME:-}" ]]; then
  if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
    export ANDROID_HOME="$ANDROID_SDK_ROOT"
  elif [[ -d /workspace/android-sdk ]]; then
    export ANDROID_HOME=/workspace/android-sdk
  else
    export ANDROID_HOME="$HOME/Android/Sdk"
  fi
fi
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export NDK_HOME="${NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

for dependency in bun cargo rustup java; do
  command -v "$dependency" >/dev/null || { printf 'Missing tool: %s\n' "$dependency" >&2; exit 1; }
done
[[ -d "$NDK_HOME" ]] || { printf 'Android NDK not found: %s\n' "$NDK_HOME" >&2; exit 1; }
[[ -d "$ANDROID_HOME/platforms/android-36" ]] || { printf 'Android platform 36 not found at %s\n' "$ANDROID_HOME" >&2; exit 1; }

rustup target add aarch64-linux-android
bun install --frozen-lockfile
bun run test:beautify
cargo test -p packet-engine -p scan-engine -p radio-engine --locked
cargo test --manifest-path tauri-plugin-capture/tests/forwarder-host/Cargo.toml --locked
bun run build
if [[ ! -f src-tauri/gen/android/gradlew ]]; then
  bunx tauri android init --ci
fi
bunx tauri android build --debug --target aarch64 --apk
printf '\nGenerated development APK(s):\n'
find src-tauri/gen/android/app/build/outputs/apk -type f -name '*.apk' -print
