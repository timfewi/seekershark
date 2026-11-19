# TCP discovery and service detection

Open **Scan**, enter one hostname, IPv4/IPv6 address, or CIDR, then choose ports and press **Scan**. Analysis endpoints also have a **Scan** action that fills the target. The scanner runs in Rust inside the Android app and does not require root, Termux, or a subprocess.

## Modes

| Mode | Behavior |
| --- | --- |
| Fast TCP | Concurrent TCP connects, similar to RustScan's discovery step. Open connections are closed immediately. Service names are explicitly labeled as port hints. |
| Service probes | After a successful connect, collect bounded server-first banners, send HTTP HEAD on selected web ports, or send a TLS 1.2 ClientHello on selected TLS ports. Observed responses are labeled separately from port hints. |

These are native SeekerShark implementations of selected RustScan/Nmap-style capabilities. The RustScan and Nmap command-line programs, Nmap service database, NSE scripts, OS fingerprinting, raw SYN scans, and UDP scans are not bundled or implemented. This is not a replacement for every Nmap `-sV` probe.

HTTP detection reads response headers, including an optional `Server` header. SSH, SMTP, FTP, POP3, IMAP, and VNC can be identified from recognizable banners. Unrecognized banners remain unidentified. Server-provided product strings are evidence reported by the peer, not authenticated software inventories.

TLS detection records a ServerHello or valid TLS alert. It offers TLS 1.2, does not complete a secure session, and does not perform certificate validation, application-protocol detection, or TLS version enumeration. A TLS response on port 443 proves a TLS endpoint responded; it does not verify HTTPS. Port hints remain separate.

## Inputs and limits

- Ports: comma-separated numbers and inclusive ranges from 1 to 65535. Overlaps are deduplicated. Presets cover common ports, 1–1024, and all TCP ports.
- Targets: one hostname or IP, or a CIDR containing at most 256 addresses. IPv4 CIDRs omit network/broadcast addresses except /31 and /32. IPv6 scope IDs and URL/port suffixes are not supported. Hostname resolution has a five-second timeout.
- At most 1,048,576 target/port checks per job. One active job at a time, with 1–256 concurrent sockets and a 15-minute time limit.
- Connect timeout: 100–10,000 ms. Optional service probe timeout: 100–5,000 ms, in addition to the connect timeout.
- At most 4096 open results retained in sorted address/port order. Counters include additional open ports; the UI and JSON disclose dropped results. The UI requests 150 results initially, with explicit pagination.
- Banner reads are capped at 2048 bytes (TLS records at 4096), displayed banners at 512 characters, and product hints at 128 characters. No response body or unbounded socket stream is stored.

Closed counts indicate connection refusal. Timeouts can result from filtering, a missing host, congestion, or a short timeout; they are not labeled as confirmed filtered ports. Other connection failures contribute to the error count. No response from the selected ports is not proof that a host is down.

**Stop scan** cancels pending connects and probes, closes active sockets, joins workers, and retains completed results. Switching tabs or using Back does not cancel the job. Keep the app in the foreground: scanning does not start a persistent Android foreground service, and Android may suspend or terminate it in the background.

Scan sockets belong to SeekerShark's own excluded UID, so they bypass its VPN capture. Scanning and capture can run independently; the app's generated scan packets will not appear in its own capture. **Filter captured packets** on a result applies that host to the packet list and preserves the return path to Scan.

## Export

**Export JSON** saves a consistent snapshot to Android Downloads/SeekerShark (app-scoped Downloads on API 28). The report includes the request, resolved addresses, timing, phase, counters, retained results, evidence labels, and any storage truncation. An export during a job is explicitly a partial report. Reports are limited to 8 MiB and are exported only on request.

## Verification

Run `cargo test -p scan-engine --locked` for local socket tests, protocol parsing, cancellation/cleanup, port/target validation, and resource bounds. `bun run test:ui` checks configuration, Back navigation, mobile controls, and the browser-only runtime limitation. Controlled IPC fixtures exercise progress, Stop, evidence rendering, export responses, and return navigation; these fixtures do not test Android networking or Downloads.

Test the signed APK against your own local services on the phone before relying on network observations. Real Android DNS, IPv6 routing, network changes, cancellation under load, and report export require device validation.
