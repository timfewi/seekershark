# Architecture

## Data flow

```text
Android apps
    │ IP packets
    ▼
Android VpnService / TUN
    │ file descriptor
    ▼
Rust TUN adapter ──► bounded capture queue
    │                         │
    ▼                         ▼
tun2proxy Direct Forwarder   packet-engine
    │ TCP/UDP                 │ checked packet decoding
    ▼                         ▼
Android network             bounded capture storage
                              │ Tauri commands / snapshots
                              ▼
                            SolidJS WebView
```

`VpnService` handles Android consent, the foreground service, and the TUN lifecycle. The native forwarder opens outgoing sockets in the app's own process. That process is excluded from the VPN, so its sockets are not routed back into the TUN. The packet tap observes both directions before passing bounded capture packets to the analyzer.

Capture runs independently of rendering. The UI requests batched snapshots and displays a limited number of rows. Details load on selection. The WebView therefore does not need to render every network read or the entire raw capture buffer.

## Rust packet decoder

The decoder treats packet contents as untrusted input. Length fields and offsets are checked before access. Supported views include IPv4/IPv6, TCP/UDP, ICMP, DNS, and basic HTTP/TLS metadata. A protocol label does not imply support for every variant or payload decryption.

PCAP files and stored IP packets use the same decoder. Captures retain raw bytes for export. List snapshots provide bounded previews; full details are requested separately. Unsupported PCAP variants return an error instead of silently assuming another format.

## Resource budgets

These values are implementation limits and development targets, **not measured performance promises**. The source code defines the actual limits and supported variants.

| Area | Budget or target | Purpose |
| --- | --- | --- |
| Native capture queue | At most 2048 packets / 8 MiB; drained in batches of up to 256 | Prevent unbounded growth when the UI is slow |
| Capture storage | Bounded ring buffer | Release oldest packets and count losses |
| Packet list | Bounded pages rather than the entire capture | Limit DOM and layout costs |
| Hex preview | Bounded previews in list snapshots | Reduce IPC volume |
| Statistics | Calculated from captured packets | Avoid fabricated live measurements |
| UI refresh | Batched, approximately once per second | Decouple capture from rendering |

Measure TCP/UDP payload throughput, p50/p95 latency, queue losses, CPU, RSS, and energy use with the packet view hidden and visible. Compare against capture disabled on the same device, network, and remote server.

## Required device validation

Android forwarding must be tested on the target device. A successful build checks compilation and packaging; it does not prove a working VPN session. Key cases include granting and denying consent, stopping from the notification, process termination, Wi-Fi/mobile handovers, IPv6, DNS, background operation, and Android revoking existing VPN permission.

## Active scanner

`crates/scan-engine` implements independent asynchronous TCP connect discovery and bounded service probes. A single managed job owns a bounded Tokio JoinSet, cancellation watch channel, counters, and up to 4096 open results. Target/port validation runs before replacing the previous report. Cancellation aborts and joins workers before another job can start. Snapshots page retained results; JSON export takes a consistent snapshot and uses Android Downloads.

Scanner sockets use the app's excluded UID and bypass its own VPN capture. The scanner does not use shell commands, external binaries, raw sockets, or Nmap databases. See [SCANNING.md](SCANNING.md) for probe semantics, budgets, and limitations.
