# Validation history

This source snapshot includes no APKs, release assets, signing keys, or prior Git history. The checks below record development work performed on its precursor versions. References to past Android builds are historical results, not a supplied binary or a fresh device-validation claim. Re-run the documented checks for any build you distribute.

## Version 0.3.0 development checks

Date: November 4, 2026. Checks ran in a Linux build environment without a connected physical Android device.

| Check | Result |
| --- | --- |
| Rust packet decoder | 18 tests passed: malformed/truncated packets, IPv4/IPv6, DNS, TLS metadata, PCAP, and memory limits |
| Rust analysis app | Android ARM64 Clippy with `-D warnings` and formatting checks passed |
| Production forwarder in host harness | TCP establishment, TCP/UDP echo through real local sockets, return traffic, queue limits, and file-descriptor cleanup passed |
| Browser UI | 14 Playwright tests passed in real Chromium on desktop and 393/320 px mobile layouts, including Beautify, Back navigation, filter/scroll restoration, and touch targets of at least 44 px |
| Scanner | 12 Rust tests passed: real local IPv4/IPv6 TCP, hostname/CIDR and port validation, SSH/HTTP probes, TLS parsing, bounded concurrency, cancellation/socket cleanup, and report serialization |
| Beautify | 12 Bun tests passed: HTTP/JSON, exact u64 numbers/duplicate keys, IPv6 extensions, VLAN/TCP options, malformed/truncated packets, UTF-8/output bounds, and encrypted protocols |
| Native Android package | Optimized release build for `arm64-v8a` passed, including native Kotlin sources |
| JNI | Three exported ARM64 symbols and their matching Kotlin JVM signatures checked |
| APK signature | Optimized preview signed with an Android development key; APK Signature Scheme v3 verified |
| 16-KiB pages | ARM64 ELF segments aligned to `0x4000`; APK passed `zipalign -c -P 16 4` |
| Android manifest | Package `dev.seekershark.app`, version 0.3.0, minimum API 28, target API 36; VPN service declares `BIND_VPN_SERVICE` and `specialUse` |

The earlier development APK was checked for signing and packaging. It is not included here. A newly built development APK has its own signature and checksum; local signing identities can differ.

Browser checks cover filters, protocol layers, hex, navigation between Analysis and the packet list, actual demo PCAP export, error messages, and horizontal overflow. Simulated browser safe areas of 28 px at the top and 24 px at the bottom leave both Back buttons reachable while packet details are scrolled. This does not verify real Android system bars, cutouts, keyboards, or Back gestures. Browser checks do not exercise Android VPN APIs. The host harness uses the production forwarder but replaces Android TUN with a local datagram file descriptor.

Still requiring device validation: status/gesture-bar spacing, Android Back, keyboard and landscape layout, VPN consent on a Solana Phone, background operation, Wi-Fi/mobile handovers, IPv6 on a real network, PCAP import through the Android file picker, Downloads export, battery usage, and throughput. See [DEVICE-TEST.md](DEVICE-TEST.md). No phone performance measurements have been recorded.

Version 0.3.0 adds native concurrent TCP discovery, selected HTTP/banner/TLS service probes, host/IP/CIDR targeting, progress, cancellation, and JSON report export. UI, source, documentation, native messages, and scripts use English. Packet list, raw/Beautify inspector, Analysis, Scan, and Session screenshots are captured from the actual Chromium interface under `docs/screenshots`. The scanner gallery image shows idle configuration; captured packet bytes retain their original contents.

Scanner browser checks use controlled IPC fixtures for progress, response evidence, Stop, export responses, and navigation. They do not verify Android networking or Android Downloads. Real socket tests run in the Rust engine on Linux. Native scanning, DNS/IPv6 routing, cancellation under device load, background suspension, and JSON report export still require physical-phone validation. See [SCANNING.md](SCANNING.md).

## Version 0.4.0 Nearby development checks

The Nearby change was checked in the cloud workspace on 2026-11-11:

- TypeScript checking and the Vite production build passed. The existing Beautify, packet-engine (18), scan-engine (12), and production-forwarder host checks passed.
- The full browser suite passed its 24 tests before the final capability-message addition; the resulting 12 Nearby cases then passed on desktop and mobile, including the new missing-Google-Play-services case. Existing packet and scan interactions remain covered. These are real Chromium UI runs; Nearby connection, pairing, sharing, and import responses use explicitly controlled IPC fixtures.
- Actual screenshots were inspected at 1440×1050, 393×852, and 320×780, plus a clearly simulated pairing screen. No horizontal clipping was observed. Screenshots of the fixture do not establish radio pairing.
- The production Rust app and bridge compiled for `aarch64-linux-android`. Native Kotlin compiled and all four `NearbyPolicyTest` JVM tests passed through `:tauri-plugin-capture:testDebugUnitTest`.
- Google Nearby Connections is pinned to **19.4.0**, which compiles with the project's Kotlin 2.2.10 compiler. Version 19.5.x uses incompatible Kotlin 2.4 metadata; no metadata checks are suppressed and the Kotlin toolchain is unchanged.
- The development ARM64 APK built with version name **0.4.0**, version code **4000**, minimum API **28**, and target API **36**. Its development signature and 16-KiB ZIP alignment were verified. The local development signer differs from the older 0.3.0 development build, so that APK cannot be updated in place with this build; export captures before replacing an installation.
- An optimized development APK passed v3 signature, checksum, ARM64-only packaging, and 16-KiB ZIP/ELF alignment checks and was not debuggable. That APK is not included in this source snapshot.

Physical two-phone discovery, permission dialogs, code comparison, offline transfer, foreground/background lifecycle, and transfer reliability remain unverified. Follow [the Nearby device test plan](DEVICE-TEST.md#nearby) before treating the feature as device-validated. These checks establish source, browser, and build behavior; they do not establish successful Bluetooth/Wi-Fi communication.

## Version 0.5.0 Radio development checks

Checked on 2026-11-17 without a connected Android phone or external Wi-Fi adapter:

- The complete **34-test Playwright suite** passed in Chromium on desktop/mobile. Radio cases cover browser limitations, six-tab navigation and touch targets at 320 px, keyboard source switching, retained BLE details while polling, start/stop/clear/export, failed operations, versioned Wi-Fi report import, and a valid empty report. Native commands use explicitly controlled IPC fixtures; these do not verify real Bluetooth reception.
- TypeScript and the Vite production build passed. Actual Radio Bluetooth and Wi-Fi scaffold screenshots were inspected at 1440×1050, 760×900, 393×852, and 320×780; no horizontal overflow was found.
- Locked Rust tests passed: **18 packet-engine + 12 scan-engine + 12 radio-engine**. The external-report parser tests enforce schema/version, size and observation bounds, timestamp order, MAC normalization, channel/frequency/band consistency, exact JavaScript-safe counters, export round trips, and preservation after invalid imports.
- The production forwarder host test and **12 Beautify tests** passed. Native Kotlin compiled and all **14 JVM tests** passed: 10 BLE aggregation/bounds/concurrency cases and four Nearby policy cases.
- The documented synthetic sensor-report example passed the production `radio-engine` validator CLI. It is a format example, not a measured capture. Live Wi-Fi capture, USB drivers, a collector daemon, and PCAP/Radiotap conversion are not implemented by this scaffold.

Android permission dialogs, location/Bluetooth toggle behavior, timed scans, screen/background handling, GMS-independent real reception, and Nearby coexistence still require the [Radio device test plan](DEVICE-TEST.md#radio-observation). Adapter recommendations are source-backed compatibility guidance, not hardware measurements performed here.

An optimized ARM64 development APK was built with version **0.5.0 / 5000**, minimum API **28**, and target API **36**. It was not debuggable and passed v3 signature, checksum, ARM64-only packaging, and 16-KiB ZIP/ELF alignment checks. The APK and its signing identity are not included in this source snapshot.
