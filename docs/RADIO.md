# Radio observation and external Wi-Fi reports

Radio observation complements the cooperative [Nearby mode](NEARBY.md). BLE observation listens for advertisements exposed by Android's Bluetooth stack; an external Wi-Fi report imports observations already collected by another system. Neither mode provides an inventory of every nearby phone, a stable identity for each observation, or access to another phone's application traffic.

## BLE observation

BLE observation uses Android's native Bluetooth APIs and does not require Google Play services or SeekerShark on the transmitting device. The transmitting device must emit advertisements that the receiver, hardware and Android stack can deliver. A result can be a phone, watch, headset, tracker, laptop or another BLE device.

- A scan lasts **10–120 seconds**, with a default of **60 seconds**, and retains at most **256 observation rows**. A row groups an observed address and advertising SID within the current scan, not a persistent physical-device identity.
- A successful new scan replaces the previous observations. Invalid settings or denied permissions preserve the previous results. Stop, timeout and Android activity backgrounding stop observation while retaining its results. Clearing is available when stopped.
- Counts refer to **Android scan reports** (delivered `ScanResult` entries, including batch results), not all over-the-air packets or a number of phones. Duplicate filtering, OS delivery, collisions, radio coverage and address rotation affect the count. A blank list is not proof that no phones are present.
- Names and public manufacturer/service metadata are observations supplied by the transmitter. They do not authenticate an owner or establish that the source is a phone. RSSI is a signal-level measurement, not a precise distance.
- Raw advertising data is limited to **512 bytes per row**, with truncation indicated. Extended advertisements and additional PHYs are requested when supported by the local hardware; otherwise scanning uses legacy capabilities.

The app requests precise location permission on supported Android versions, plus nearby Bluetooth permissions on Android 12 or later. This is required for the broader observation configuration; the app does not read GPS coordinates. Turn on both Bluetooth and Android Location services. The shared Bluetooth permission configuration also affects Nearby. Android can restrict delivery in background or screen-off states. The app uses a bounded foreground scan rather than promising continuous background discovery.

Android scanning may transmit scan requests to receive additional scan-response data. **BLE observation is not a guarantee of RF-silent passive reception.** The API provides decoded advertising data, RSSI and timestamps, not raw I/Q samples or a hardware-fingerprint measurement. See Android's [Bluetooth scan API](https://developer.android.com/reference/android/bluetooth/le/BluetoothLeScanner), [scan results](https://developer.android.com/reference/android/bluetooth/le/ScanResult) and [permission guidance](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions).

## External Wi-Fi report import

The Wi-Fi part is a **report-import interface**, not a live Wi-Fi sniffer. This build does not contain a Linux capture daemon, a PCAP-to-report converter, an Android monitor-mode driver, or a live sensor connection. A separate collector must produce the versioned JSON format below; transfer the file and import it explicitly. Export saves the accepted report as JSON through Android Downloads.

The imported report remains separate from VPN packet analysis and BLE observation. It describes what the source sensor claims to have observed. Its adapter/driver labels are provenance supplied by the file, not a hardware attestation. Address observations must not be displayed or interpreted as an exact count of unique phones.

### Version 1 JSON format

The complete file must be valid UTF-8 JSON and at most **1 MiB**, including its canonical exported form. There may be up to **2,048 unique transmitter-address observations**. The following is a synthetic format example, not a recorded capture:

```json
{
  "schemaVersion": 1,
  "source": "external-wifi-sensor",
  "sensor": {
    "id": "lab-sensor-1",
    "label": "Example Linux sensor",
    "adapter": "ALFA AWUS036ACM / MT7612U",
    "driver": "mt76x2u",
    "bands": ["2.4GHz"],
    "channels": [6]
  },
  "startedAt": 1700000000000,
  "endedAt": 1700000001000,
  "observations": [
    {
      "transmitter": "02:11:22:33:44:55",
      "firstSeen": 1700000000000,
      "lastSeen": 1700000001000,
      "frames": 3,
      "rssiDbm": -55,
      "channel": 6,
      "frequencyMhz": 2437,
      "frameTypes": ["probe-request"]
    }
  ]
}
```

Timestamps are integer Unix milliseconds, ordered within the report's start/end bounds, from `0` through `4102444800000`. A transmitter must be a nonzero unicast MAC address; accepted addresses are normalized to lowercase. Duplicate addresses in one report are rejected. A randomized address is accepted as an observed identifier without claiming that it is permanent.

Sensor ID is limited to 64 characters; label, adapter and driver to 128 each. Bands contain one to three distinct values from `2.4GHz`, `5GHz`, and `6GHz`; channels contain one to 256 distinct integers compatible with those bands. Each observation's band/channel must be declared in the sensor metadata. Frame types contain one to 32 distinct strings of at most 48 characters each; frames is a positive integer no greater than 9,007,199,254,740,991 so JSON counters remain exact in JavaScript. RSSI is `null` or a finite number from −127 through +20 dBm. Text fields reject control characters.

The parser checks channel/frequency consistency. It accepts 2.4 GHz channels 1–13 as `2407 + 5 × channel` MHz and channel 14 as 2484 MHz; 5 GHz channels 32–177 as `5000 + 5 × channel` MHz; 6 GHz channels 1–233 as `5950 + 5 × channel` MHz, with channel 2 at 5935 MHz. These are format-validation ranges, **not authorization or a regulatory promise that every listed channel is available in the user's country**.

Invalid imports leave the previous accepted report intact. JSON metadata does not replace or decrypt packet captures; classic PCAP import remains a separate feature.

## External adapter recommendation

For an initial external Linux sensor covering **2.4 and 5 GHz**, the recommended starting point is the **ALFA AWUS036ACM with the MediaTek MT7612U chipset**. Connect it to a Linux laptop or a Raspberry Pi running a current, maintained Linux distribution with the matching driver and firmware. A separately powered USB hub can help when the host's power budget is limited. Use another interface for the sensor's normal network connection so capture-channel changes do not break its uplink.

The following checks were researched against manufacturer documentation and Linux sources on **2026-11-17**. No adapter was physically tested in this workspace. The exact model suffix and received chipset matter; similarly named adapters can use different drivers.

| Exact adapter/chip to verify | Linux driver | Radio bands | Monitor-observation evidence and tradeoff |
| --- | --- | --- | --- |
| **ALFA AWUS036ACM / MT7612U**, USB `0e8d:7612` | `mt76x2u`, in the mainline `mt76` family | 2.4 / 5 GHz; no 6 GHz | Preferred initial choice. ALFA documents mainline support from Linux 4.19; the kernel's USB device table explicitly identifies this model. The mac80211 stack supports monitor interfaces. Verify the actual firmware, channel operation and received frames on the selected host. |
| **ALFA AWUS036NHA / AR9271** | `ath9k_htc` with AR9271 firmware | 2.4 GHz only | Linux Wireless explicitly lists monitor mode. Useful if already owned, but it misses 5/6 GHz and ALFA now marks the model **EOL**, so it is not the preferred new purchase for broad coverage. |
| **ALFA AWUS036AXML / MT7921AUN**, USB `0e8d:7961` | `mt7921u` in the `mt76` family | Advertised 2.4 / 5 / 6 GHz | A candidate when 6 GHz is specifically required, subject to the current kernel/firmware and regional channel rules. Wi-Fi 6E branding does not establish complete or RF-silent monitor coverage. Treat it as a separate validation target rather than promising plug-and-play passive operation. |

Sources: ALFA's [AWUS036ACM specification](https://www.alfa.com.tw/products/awus036acm) and [MT7612U Linux support](https://docs.alfa.com.tw/Support/Linux/MT7612U/); Linux's [mt76x2 USB device table](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/wireless/mediatek/mt76/mt76x2/usb.c) and [mac80211 monitor registration](https://raw.githubusercontent.com/torvalds/linux/master/net/mac80211/main.c); ALFA's [AWUS036NHA EOL page](https://www.alfa.com.tw/products/awus036nha) and Linux's [ath9k_htc features](https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath9k_htc.html); ALFA's [AWUS036AXML specification](https://www.alfa.com.tw/products/awus036axml) and Linux's [MediaTek driver documentation](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mediatek.html).

For MT7921/MT7925-based adapters, current Linux source disables advertisement of **active monitor** support; this is distinct from ordinary passive monitor reception. A May 2026 report on the Linux MediaTek mailing list also describes unexpected RF bursts when retuning certain MT7921/MT7925 monitor setups, including an AWUS036AXML. That is a reported configuration-dependent issue, not proof that every unit or current firmware behaves identically. Verify the chosen kernel/firmware combination before claiming RF-silent collection. Sources: [current mt792x initialization](https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/wireless/mediatek/mt76/mt792x_core.c), [original monitor-retune report](https://lists.infradead.org/pipermail/linux-mediatek/2026-May/107387.html).

### Why a USB-C adapter is not automatically supported on Seeker

Android USB host support can enumerate a USB device and grant an app access to its endpoints. It does not install `mt76x2u`, `ath9k_htc`, or firmware in the phone's kernel. Direct capture would need a compatible Android kernel driver and usable monitor interface, or a separately implemented userspace USB/radio driver. USB permissions and root access alone do not provide these components. This build implements neither direct USB Wi-Fi capture path. See Android's [USB host API](https://developer.android.com/develop/connectivity/usb/host).

The practical initial arrangement is therefore **Linux host + supported adapter → collector-generated JSON file → SeekerShark report import**. A live transport can later reuse the report model, but it is not part of this interface yet.

## Coverage limits and validation

A single receiver normally observes its currently tuned channel and supported PHY/bandwidth. Changing channels creates observation gaps; dual-band capability does not mean simultaneous monitoring of every 2.4/5 GHz channel. A 2.4-only or 2.4/5 GHz adapter has no 6 GHz coverage. Modern PHY features and channel widths can further limit what an older receiver decodes.

Rotating identifiers, multiple interfaces, packet loss, radio silence, and signals from non-phone devices prevent a guaranteed all-phone count. Observing an address also does not grant access to encrypted WLAN or HTTPS contents. Validate with a known set of devices, recorded radio states, host/kernel/firmware versions and documented channel dwell periods; see the [device test plan](DEVICE-TEST.md#radio-observation).
