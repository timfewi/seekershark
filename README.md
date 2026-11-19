# SeekerShark

See where your Android phone connects and inspect the packets it sends and receives. SeekerShark uses Android’s VPN feature to record traffic locally. You can export a capture as a PCAP file and open it in Wireshark.

[See SeekerShark in action](docs/screenshots/README.md)

## Quick demo

Preview the interface in your browser with Bun 1.4.4. The demo uses synthetic packet data. Live capture and radio observation require the Android app.

```sh
git clone https://github.com/timfewi/seekershark.git
cd seekershark
bun install --frozen-lockfile
bun run dev
```

Open the local address printed by Vite. You can filter packets, inspect protocol fields and hex, and export the demo as a PCAP.

## Explore the app

- **Packets and Analysis** show where traffic goes, which protocols it uses, and how much data moves. Encrypted content stays encrypted.
- **Scan** checks which TCP services respond at an address you specify. [Scan guide](docs/SCANNING.md)
- **Nearby** shares a capture with another phone running SeekerShark after both users confirm a pairing code. The phones can connect without a shared Wi-Fi network. [Sharing guide](docs/NEARBY.md)
- **Radio** shows received Bluetooth LE broadcasts and opens reports collected by a separate Wi-Fi sensor. [Radio guide](docs/RADIO.md)

## Build and install on Android

Build the development APK locally for ARM64 phones running Android 9 or later, including Solana Seeker.

Install Rust 1.99.1 with the `aarch64-linux-android` target, Bun 1.4.4, Java 21, and Android SDK platform 36 with Build Tools 36.0.0 and NDK 27.2.12479018. Run the build script with `ANDROID_HOME` set to your SDK directory.

```sh
./scripts/build-android.sh
```

The script prints the path to the debug-signed development APK. Transfer that APK to your phone and open it, or enable USB debugging and run `adb install -r /path/to/the-built.apk`. Allow installation from the file app if Android asks.

Tap **Capture** and approve Android's local VPN request. Open a packet to inspect it, tap **Stop** to end capture, and use **Export** to save a PCAP. If an existing installation uses a different signing key, export captures you want to keep before uninstalling it. Uninstalling removes app-local data.

[Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md) · [Validation](docs/VALIDATION.md) · [Device test plan](docs/DEVICE-TEST.md)

## Privacy and license

Packet analysis runs on your phone. Captures and radio reports can contain network identifiers or readable data. Review files before sharing them. Google Play services may collect usage diagnostics when you use Nearby. [Nearby usage diagnostics](https://developers.google.com/nearby/connections/overview#data_collection)

SeekerShark’s source code is licensed under [MIT](LICENSE). Its dependencies have their own terms. [Third-party notices](docs/THIRD-PARTY.md)
