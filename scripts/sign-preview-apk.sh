#!/usr/bin/env bash
# Development signing only. Production/store builds need a separate private key.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'Usage: %s unsigned.apk output-preview.apk\n' "$0" >&2
  exit 1
fi
sdk_dir="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
tools_dir="$sdk_dir/build-tools/36.0.0"
preview_key="$HOME/.android/debug.keystore"
[[ -f "$1" ]] || { printf 'APK not found: %s\n' "$1" >&2; exit 1; }
[[ -x "$tools_dir/apksigner" && -x "$tools_dir/zipalign" ]] || { printf 'Android Build Tools 36.0.0 not found.\n' >&2; exit 1; }

if [[ ! -f "$preview_key" ]]; then
  mkdir -p "$(dirname "$preview_key")"
  (umask 077; keytool -genkeypair -keystore "$preview_key" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname 'CN=Android Debug,O=Android,C=US')
fi

aligned_apk="$(mktemp --suffix=.apk)"
trap 'rm -f "$aligned_apk"' EXIT
"$tools_dir/zipalign" -P 16 -f 4 "$1" "$aligned_apk"
"$tools_dir/apksigner" sign --ks "$preview_key" --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android --out "$2" "$aligned_apk"
"$tools_dir/apksigner" verify --verbose "$2"
"$tools_dir/zipalign" -c -P 16 4 "$2"
printf '\nOptimized development APK: %s\n' "$2"
