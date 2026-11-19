# Contributing to SeekerShark

Start with the [browser demo](README.md#quick-demo) to work on the interface. Build the [Android app](README.md#build-and-install-on-android) to work on VPN capture, Nearby sharing, or Bluetooth observation.

## Find the code

| Directory | What lives there |
| --- | --- |
| `src/` | SolidJS interface, packet views, and browser demo |
| `crates/` | Rust packet decoding, TCP discovery, and radio report validation |
| `src-tauri/` | Tauri app, commands, and Android project |
| `tauri-plugin-capture/` | Android VPN, packet forwarding, Nearby, and BLE |
| `docs/` | Feature guides, architecture, and device test plan |

## Run the checks

Use Bun 1.4.4 and Rust 1.99.1. The source workflow runs these checks for pull requests.

```sh
bun install --frozen-lockfile
bun run build
bun run test:beautify
bunx playwright install chromium
bun run test:ui
cargo test -p packet-engine -p scan-engine -p radio-engine --locked
cargo test --manifest-path tauri-plugin-capture/tests/forwarder-host/Cargo.toml --locked
```

For native behavior, follow the relevant section of the [device test plan](docs/DEVICE-TEST.md).

When filing an issue, include the steps to reproduce it, your app version, and your Android version or browser. Use synthetic traffic for examples you share publicly.
