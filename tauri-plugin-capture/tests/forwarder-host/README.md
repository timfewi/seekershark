Run from the repository root:

```sh
cargo test --locked --manifest-path tauri-plugin-capture/tests/forwarder-host/Cargo.toml
```

The Linux test needs no root privileges, emulator, or Internet access. It uses
the production forwarding module and checks both capture directions, bounded
capture memory, sample loss under pressure, real UDP forwarding to a local echo
socket, and a full TCP handshake and echoed payload through a local TCP server.
It validates the return IP/TCP packets and descriptor cleanup after stop.

This validates the Rust forwarding path. Android consent, VPN routing,
foreground-service behavior and hardware throughput require device testing.
