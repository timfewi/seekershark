# Nearby capture sharing

Nearby connects two Android phones running SeekerShark so one can explicitly send a capture to the other for analysis. It uses Google Nearby Connections, which negotiates local Bluetooth/BLE and Wi-Fi links. The phones do not need to join an existing shared Wi-Fi network or have internet access for the transfer.

This is cooperative discovery of SeekerShark peers. A phone appears only when it participates in this feature; the list is not an inventory of all phones in radio range. Nearby does not enable remote recording, Wi-Fi monitor mode, or access to the other phone's applications and files.

## Requirements

- [Build and install this source version](../README.md#build-and-install-on-android) on both phones. Nearby requires SeekerShark on each participant; no prebuilt APK is included in this snapshot.
- Use Android 9 (API 28) or later, compatible Bluetooth/Wi-Fi hardware, and available Google Play services.
- Enable the requested radios and grant the Android permissions shown by the feature. Precise location permission is required on all supported Android versions because the app also supports broad BLE observations without the filtering `neverForLocation` assertion. Newer Android versions additionally request nearby Bluetooth/Wi-Fi permissions; API 32 and earlier request file access for Nearby transfers. Denying a required permission prevents Nearby from starting. These features do not collect location coordinates.
- Keep both apps in the foreground while pairing and transferring. When the Android activity stops, Nearby disconnects and deletes temporary transfer files, including unopened received captures. Switching SeekerShark tabs does not stop Nearby.

The browser demo cannot discover or connect to real phones.

## Connect and share

1. Open **Nearby** on both phones, enter **Your device name**, and tap **Start Nearby**.
2. Tap **Connect** for the intended peer. Compare the authentication code displayed on both screens and tap **Confirm code** on each phone only when the codes match. Use **Reject** if they do not match or the request is unexpected. A device name alone does not authenticate its owner.
3. On the sending phone, record traffic through SeekerShark's local VPN or open a PCAP. Review the capture and tap **Share current capture** for the connected peer. Connecting by itself sends no capture.
4. On the receiving phone, wait for the file to finish in **Capture transfers**, the temporary Nearby inbox. Receiving a file does not replace the packet list.
5. Stop any active local capture, then tap **Open capture** on the received file. Opening replaces the displayed capture, so export it first if you want to keep it. Analyze the imported file with the existing packet, filter, hex, and statistics views. Encrypted TLS/QUIC payloads remain encrypted. **Discard** removes an unopened received file.
6. Use **Stop Nearby** when finished. A lost connection or interrupted transfer requires reconnecting and sending again; it is not a live synchronized capture.

Sharing takes a snapshot of the capture retained by the app. It does not send every packet ever observed or stream packets as they arrive. Packet retention and PCAP decoder limits still apply after transfer.

Each phone advertises and discovers the SeekerShark service after **Start Nearby**. Only one peer can be connected at a time; discovery and visibility pause while connected and resume automatically after disconnecting. If discovery cannot resume, the app reports an error; check Bluetooth and Wi-Fi, then start Nearby again. Pending connection requests expire after **60 seconds**.

**Stop Nearby** also clears the temporary inbox and outgoing transfer files. Open a received capture you want to keep before stopping Nearby or leaving the app; export the imported capture if you need a saved copy. The packet analysis already imported into the app is separate from the temporary inbox.

## File and retention limits

- Nearby accepts classic PCAP files up to **40 MiB**, including file and packet-record headers. PCAPNG is not supported. An empty capture cannot be shared.
- There are **3 receive/inbox slots**, up to **8 transfer records**, and up to **32 discovered peers**. Use **Discard** to free an unopened inbox slot. The device list is bounded and does not represent every phone nearby.
- Analysis retains at most **10,000 packets / 32 MiB of packet bytes**. Imported files may contain more records than are retained; the decoder processes at most **1,000,000 records**. These analysis limits are distinct from the transfer-size limit.
- Import is blocked while local capture is running or starting. A parse failure preserves the existing displayed capture and the inbox entry. After a successful import, the received file is removed from the temporary inbox.

## Discovery, scanning, and packet capture

| Operation | What it can establish |
| --- | --- |
| Nearby discovery | Another participating SeekerShark instance is reachable through the local discovery mechanism. Its display name does not prove identity. |
| TCP scan | An IP address/hostname is reachable and a selected TCP port responds. A shared Wi-Fi is not mandatory if routing allows access. |
| Local VPN capture | IP traffic routed through that phone's SeekerShark VPN. |
| Nearby PCAP import | Packets that the sending phone recorded or imported and chose to share. |

Nearby discovery does not expose a peer's general network traffic or automatically provide a scan target. A phone beside you on mobile data or another Wi-Fi network may sit behind NAT/CGNAT or an inbound firewall. Even on one Wi-Fi, client isolation or closed ports can prevent responses. No response is not proof that a phone is absent.

Creating a hotspot also does not automatically route clients' forwarded traffic through the host phone's `VpnService`. The host's existing capture is not a capture of every hotspot client. Each participating phone records its own traffic and shares the resulting PCAP explicitly.

## Validation

The [device test plan](DEVICE-TEST.md#nearby) covers permissions, code confirmation, transfer, import, and interrupted sessions. Source checks and browser fixtures cannot establish real radio discovery, Google Play services behavior, or transfer reliability between physical phones. Record physical-device results only after performing them.

Google's [Nearby Connections overview](https://developers.google.com/nearby/connections/overview) and [Android setup guide](https://developers.google.com/nearby/connections/android/get-started) describe the underlying transport and permission requirements.
