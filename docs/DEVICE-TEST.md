# Testing on a Solana Phone

This is a test plan. Mark a result as passed only after actually performing the check.

1. [Build and install the development APK](../README.md#build-and-install-on-android). Record the app version, phone model, and Android version. Updating with `adb install -r` requires the same signing identity as the installed app.
2. With capture disabled, open an HTTPS page and download a file. Record DNS, IPv4/IPv6, and network type.
3. Start capture and deny Android VPN consent. The app must display the error while internet access continues to work.
4. Start again and grant consent. Check the foreground notification and Android VPN indicator. Trigger a DNS query, HTTPS request, and larger TCP transfer from another app.
5. Check that packet and byte counts increase. Open DNS, TCP/TLS, and UDP packets; compare addresses and ports with the generated traffic.
6. Stop capture in the app. Check that the VPN and notification disappear and internet access remains available.
7. Start again and stop from the notification. Then capture again. No stale file descriptor or duplicate forwarder should remain active.
8. During capture, switch between Wi-Fi and mobile data, lock the screen, and put the app in the background. Record behavior and any connectivity failures.
9. Export a capture and open it in Wireshark. Compare packet count, timestamps, link type, and original/captured lengths. Import the same file into SeekerShark.
10. Generate a long capture and high load. Observe memory use and queue losses. The app must expose its limits instead of using unbounded memory.

For throughput comparisons, perform at least three runs without the VPN and three with capture enabled on the same network against the same test server you control. Cover both directions, UDP and TCP, and the packet inspector open and closed. Do not derive throughput claims from the phone's theoretical bandwidth.

ICMP/ping forwarding is not supported in this version. Encrypted payloads remain encrypted; an empty TLS payload view is not evidence of a defect.

## Mobile controls

- Check portrait and landscape orientation, gesture navigation, and three-button navigation. Status icons, display cutouts, and the navigation bar must not overlap Capture, Back, or the bottom navigation.
- Use Open, Export, Clear, Capture, filter help, and Beautify with a finger. Enter a filter with the keyboard visible, then dismiss the keyboard.
- Open a packet, enable Beautify, scroll to the end, and return with the fixed bottom Back button. Repeat using the top Back button and Android's Back gesture. The filter and list position must be preserved.
- From Analysis, open a protocol or endpoint, then a packet. Repeated Back actions must return to the filtered list, then Analysis, then the original list with its filter and scroll position.
- Open Session and use Back to restore the previous view. If filter help is open, Back closes it first.
- At the main packet list with no open subview, Android Back uses normal Android behavior. Navigation alone must not stop an active capture; its VPN notification must remain accessible.

## English language

- Check controls, accessibility labels, field explanations, empty states, capture errors, and notification actions. SeekerShark-authored text must be English, including on a phone configured for another language.
- Check number grouping, packet summaries, and the synthetic demo. Captured network payloads and operating-system-owned dialogs retain their original content or system language.

## Scanner

- Run Fast TCP against known open and closed ports on a local server. Compare results with a TCP connect scan from another device. Check literal IPv4, IPv6, a hostname, and a small CIDR.
- Enable Service probes and check known SSH/HTTP/TLS servers. Verify port hints remain labeled when no response identifies a service; a TLS response must not be presented as verified HTTPS.
- Start a longer scan, switch tabs, return, and cancel. Progress must remain consistent; Stop must close pending sockets before another job starts. Check foreground/background transitions and network changes.
- Scan an endpoint from Analysis and use Filter captured packets on a result. Back must restore the originating view and scan state.
- Export a completed and a cancelled/partial JSON report to Downloads, open them, and compare target, counters, evidence, and retained results with the UI.
- Check one target on an isolated Wi-Fi client or behind an inbound firewall. Timeouts must not be presented as proof that the phone is absent. A scan result must not imply access to that phone's traffic.

## Nearby

Use two physical Android phones with builds containing Nearby. Record both models, Android versions, app versions, Google Play services versions, and granted permissions. Cover API 28 and current Android permission behavior where devices are available. These are planned checks, not completed validation.

- Start Nearby on both phones without joining the same existing Wi-Fi. With mobile data/internet unavailable, discover the participating peer, connect, and transfer a capture. Only participating SeekerShark peers should appear; do not interpret an empty list as no phones nearby.
- Deny each runtime permission, retry, then grant it through the supported flow. Check permanently denied permissions, disabled Bluetooth/Wi-Fi, and location services where required by the Android version. Missing or unavailable Google Play services must produce a usable error and leave local capture/import usable.
- Request a connection and compare codes on both phones. Confirm matching codes on both sides. Reject on each side in separate runs, cancel a pending connection, and never confirm a mismatched code. Rejection must leave no authenticated peer or enabled sharing action. A failed attempt must permit a fresh pairing attempt.
- Let a connection request expire after 60 seconds. Check the single-peer limit and that discovery/visibility pause while connected. After disconnecting, verify advertising/discovery resume automatically; if resuming fails, check the error and retry with **Stop Nearby** and **Start Nearby**.
- Connect without sending. No PCAP should arrive, and neither phone should begin recording solely because it paired. Capture traffic on the sender, explicitly share it, and compare the completed inbox file with the sent snapshot.
- Transfer a small valid PCAP and a larger valid PCAP near the 40 MiB transfer limit. Use **Open capture** with local capture stopped; compare addresses, timestamps, packet contents, and retained packet count with the source, accounting for the 10,000-packet / 32 MiB analysis limit. Encrypted payloads must remain encrypted.
- Check invalid/truncated PCAP data, PCAPNG, empty captures, and files exceeding 40 MiB. Failures must be explicit and must preserve the current packet list. A decoder failure must leave the inbox entry available for **Discard**. Verify that malformed input cannot become an active capture or an accepted decoded packet list.
- Receive a valid file while local capture is running or starting. Reception must not silently replace the local capture; stop recording before **Open capture**. Check successful import removes its temporary inbox entry, **Discard** removes an unopened file, and repeated sends do not confuse an earlier file with a new transfer.
- Stop Nearby, disconnect, disable a radio, move out of range, and close/restart the app during pairing and transfer in separate runs. Incomplete files must not appear as complete; temporary data and stale peers must be cleaned up. Reconnect and verify a new transfer succeeds.
- Fill the three receive/inbox slots. Further files must fail explicitly instead of using unbounded storage; **Discard** must free a slot. Check bounded transfer history and the distinction between a temporary received file and an already imported analysis.
- Switch tabs and exercise Android Back, screen rotation, locking, and background/foreground transitions. Changing tabs must keep Nearby available. When the activity stops or **Stop Nearby** is used, connections and temporary files, including unopened inbox files, must be cleared. Stopping Nearby must not stop a separately running local VPN capture.
- Confirm hotspot clients' traffic is not represented as automatically captured through the host's VPN. Nearby sharing must remain an explicit transfer of the sender's own retained capture, not remote capture or TLS decryption.

## Radio observation

Use a recorded set of phones and non-phone BLE devices. Record the Seeker model, Android version, Bluetooth hardware capabilities, app version, permission choices and device radio states. These are planned physical-device checks, not completed measurements.

- Start a BLE scan with another phone advertising a known test service and no SeekerShark installation. Observe that it can appear without pairing or a shared WLAN. Also include a headset or tracker; the UI must not turn all results into a claimed phone count.
- Check the 10- and 120-second duration bounds, the default duration, timeout and explicit Stop. A successful new scan should reset only its scan-local observations. Invalid settings and denied permissions must preserve previous results. Stop/backgrounding must retain observations while ending scanning; Clear must be available when stopped.
- Deny precise location and nearby Bluetooth permissions individually; retry through the supported flow. Check Bluetooth off, unavailable hardware and location-services requirements on the tested OS. BLE observation must work independently of Google Play services and must not read GPS coordinates.
- Confirm BLE and Nearby cannot start conflicting scans or overlapping permission dialogs. Test each start order, cancellation and denial; each feature must remain usable after the other stops.
- Test screen off, app backgrounding, Android Back and tab changes. Observe actual callback delivery rather than assuming continuous background scanning. Verify that stopping radio observation does not stop an independent VPN capture.
- Observe address rotation and, where available, different advertising SIDs from the same controlled device. Results must remain temporary observations, with no promise of a persistent identity. Check the 256-row cap, callback counter semantics, truncated advertising bytes and available legacy/extended PHY behavior.
- Export a BLE report and compare names, RSSI, first/last-seen information and callback counts with the visible observations. Check that omitted or truncated fields are represented honestly. Do not infer exact range or count all nearby phones from the report.
- For Wi-Fi report import, use the synthetic example in [RADIO.md](RADIO.md#version-1-json-format), then a report generated by a sensor under your control. Verify source labels, declared bands/channels, timestamps, frame types and address observations remain separate from the current VPN packet capture and BLE list.
- Reject malformed/oversized JSON, wrong schema/source, duplicate or invalid transmitter addresses, unordered/out-of-range timestamps, non-finite RSSI, incompatible channel/frequency/band combinations, control characters and excess rows. A failed import must preserve the previous report. Export/reimport an accepted report and compare its contents.
- Before using an external adapter, record its exact model, chipset/USB ID, host kernel, driver and firmware. Verify monitor support and received known frames on each band/channel of interest; a USB device merely appearing is insufficient. The current app must not claim a live connection or direct USB-C Wi-Fi capture.
- Compare a fixed-channel recording against channel-hopping runs with known devices. Document missed observations and radio-silent states. An empty report or an adapter without 6 GHz support must never become a claim that no phones are nearby.
