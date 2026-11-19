//! Rootless Android forwarding and a bounded, non-blocking capture tap.
//!
//! The VPN builder must exclude this application's package. The forwarding
//! sockets then use Android's underlying network instead of entering the VPN.
//! The passed descriptor is owned by this module, including on startup failure.

use crate::{CaptureStats, RawPacket};
use std::{
    collections::VecDeque,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    sync::{mpsc, Mutex, OnceLock},
    task::{Context, Poll},
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun2proxy::CancellationToken;

const MTU: u16 = 1500;
const MAX_QUEUE_PACKETS: usize = 2048;
const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DRAIN_PACKETS: usize = 256;

#[derive(Default)]
struct State {
    generation: u64,
    stats: CaptureStats,
    packets: VecDeque<RawPacket>,
    shutdown: Option<CancellationToken>,
    worker: Option<JoinHandle<()>>,
}

struct WorkerExitGuard(u64);

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        let mut capture = locked();
        if capture.generation == self.0 && capture.stats.running {
            capture.stats.running = false;
            capture.stats.last_error = Some("The forwarding worker terminated unexpectedly".into());
            capture.shutdown = None;
        }
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}

fn locked() -> std::sync::MutexGuard<'static, State> {
    // Preserve teardown and descriptor ownership even after an unrelated panic.
    state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Transfer ownership of an Android VpnService TUN file descriptor and start
/// TCP/UDP forwarding. Returns only after the async device is ready.
pub fn start(fd: i32) -> Result<(), String> {
    if fd < 0 {
        return Err("Android did not provide a valid VPN descriptor".into());
    }
    // SAFETY: Java passes a detached descriptor exactly once. This function
    // takes ownership on every path, so Java must not close or reuse it.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let shutdown = CancellationToken::new();
    let generation = {
        let mut capture = locked();
        if capture.stats.running {
            return Err("A capture is already running".into());
        }
        capture.worker.take();
        capture.generation = capture.generation.wrapping_add(1);
        capture.packets.clear();
        capture.stats = CaptureStats {
            running: true,
            ..Default::default()
        };
        capture.shutdown = Some(shutdown.clone());
        capture.generation
    };
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let worker_shutdown = shutdown.clone();
    let worker = std::thread::Builder::new()
        .name("seekershark-vpn".into())
        .spawn(move || {
            let _exit_guard = WorkerExitGuard(generation);
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let message = format!("Could not start forwarding runtime: {error}");
                    let _ = ready_tx.send(Err(message.clone()));
                    finish(generation, Some(message));
                    return;
                }
            };
            let result = runtime.block_on(async {
                let mut config = tun::Configuration::default();
                // Keep OwnedFd alive until the async device has been dropped.
                // This also closes the descriptor if device creation fails.
                config.raw_fd(owned_fd.as_raw_fd()).close_fd_on_drop(false);
                let device = match tun::create_as_async(&config) {
                    Ok(device) => device,
                    Err(error) => {
                        let message = format!("Could not open the Android VPN: {error}");
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                };
                let args = tun2proxy::Args {
                    proxy: tun2proxy::ProxyParameters::new(tun2proxy::ProxyType::None, None, None),
                    setup: false,
                    ipv6_enabled: true,
                    dns: tun2proxy::ArgDns::Direct,
                    dns_addr: "1.1.1.1".parse().expect("constant DNS address"),
                    max_sessions: 512,
                    tcp_timeout: 120,
                    udp_timeout: 30,
                    verbosity: tun2proxy::LevelFilter::Warn,
                    ..Default::default()
                };
                if ready_tx.send(Ok(())).is_err() {
                    return Ok(());
                }
                tun2proxy::run(
                    TapDevice {
                        inner: device,
                        generation,
                    },
                    MTU,
                    args,
                    worker_shutdown.clone(),
                )
                .await
                .map(|_| ())
                .map_err(|error| format!("VPN forwarding stopped: {error}"))
            });
            // Cancellation aborts all sessions in tun2proxy::run. Bound runtime
            // cleanup too, so service shutdown does not depend on remote peers.
            runtime.shutdown_timeout(Duration::from_secs(2));
            drop(owned_fd);
            finish(generation, result.err());
        });
    match worker {
        Ok(worker) => locked().worker = Some(worker),
        Err(error) => {
            let message = format!("Could not create forwarding thread: {error}");
            finish(generation, Some(message.clone()));
            return Err(message);
        }
    }
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => result,
        Err(_) => {
            shutdown.cancel();
            Err("VPN forwarding did not become ready within five seconds".into())
        }
    }
}

fn finish(generation: u64, error: Option<String>) {
    let mut capture = locked();
    if capture.generation == generation {
        capture.stats.running = false;
        capture.stats.last_error = error;
        capture.shutdown = None;
    }
}

/// Stop forwarding, release all session sockets, and close the VPN descriptor.
/// Captured packets remain available to drain after stop.
pub fn stop() {
    let worker = {
        let mut capture = locked();
        if let Some(shutdown) = capture.shutdown.as_ref() {
            shutdown.cancel();
        }
        capture.worker.take()
    };
    if let Some(worker) = worker {
        let _ = worker.join();
    }
}

pub fn status() -> CaptureStats {
    locked().stats.clone()
}

/// Drain at most 256 packets per IPC call. Sampling loss is reported separately
/// from traffic; the queue never applies backpressure to packet forwarding.
pub fn drain() -> (Vec<RawPacket>, CaptureStats) {
    let mut capture = locked();
    let count = MAX_DRAIN_PACKETS.min(capture.packets.len());
    let packets: Vec<_> = capture.packets.drain(..count).collect();
    let bytes = packets
        .iter()
        .map(|packet| packet.data.len())
        .sum::<usize>();
    capture.stats.queued_bytes = capture.stats.queued_bytes.saturating_sub(bytes);
    capture.stats.queued_packets = capture.packets.len();
    (packets, capture.stats.clone())
}

fn sample(generation: u64, bytes: &[u8]) {
    // This critical section only moves/copies a single packet and never performs
    // parsing, serialization or I/O. Keep forwarding independent of UI polling.
    let mut capture = locked();
    if capture.generation != generation || !capture.stats.running || bytes.is_empty() {
        return;
    }
    capture.stats.received_packets = capture.stats.received_packets.saturating_add(1);
    capture.stats.received_bytes = capture
        .stats
        .received_bytes
        .saturating_add(bytes.len() as u64);
    if capture.packets.len() >= MAX_QUEUE_PACKETS
        || capture.stats.queued_bytes.saturating_add(bytes.len()) > MAX_QUEUE_BYTES
    {
        capture.stats.dropped_packets = capture.stats.dropped_packets.saturating_add(1);
        return;
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    capture.stats.queued_bytes += bytes.len();
    capture.packets.push_back(RawPacket {
        timestamp,
        data: bytes.to_vec(),
    });
    capture.stats.queued_packets = capture.packets.len();
}

struct TapDevice<D> {
    inner: D,
    generation: u64,
}

impl<D: AsyncRead + Unpin> AsyncRead for TapDevice<D> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let previous = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            sample(self.generation, &buf.filled()[previous..]);
        }
        result
    }
}

impl<D: AsyncWrite + Unpin> AsyncWrite for TapDevice<D> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            sample(self.generation, &buf[..*written]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// These JNI symbols are linked into the application's Tauri native library.
// Java loads that library before requesting consent or creating the service.
pub fn ensure_linked() {
    // Keep JNI entry points reachable from the Rust plugin as well as Java.
    std::hint::black_box(Java_dev_seekershark_capture_CaptureVpnService_nativeStart as *const ());
    std::hint::black_box(Java_dev_seekershark_capture_CaptureVpnService_nativeStop as *const ());
    std::hint::black_box(Java_dev_seekershark_capture_CaptureVpnService_nativeStatus as *const ());
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_seekershark_capture_CaptureVpnService_nativeStart(
    env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
    fd: jni::sys::jint,
) -> jni::sys::jstring {
    match start(fd) {
        Ok(()) => std::ptr::null_mut(),
        Err(error) => env
            .new_string(error)
            .map(|text| text.into_raw())
            .unwrap_or(std::ptr::null_mut()),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_seekershark_capture_CaptureVpnService_nativeStop(
    _env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) {
    stop();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_seekershark_capture_CaptureVpnService_nativeStatus(
    env: jni::JNIEnv<'_>,
    _class: jni::objects::JClass<'_>,
) -> jni::sys::jstring {
    let json = serde_json::to_string(&status()).unwrap_or_else(|_| "{\"running\":false}".into());
    env.new_string(json)
        .map(|text| text.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn wait_for_samples(expected: u64) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let stats = status();
                if stats.received_packets >= expected {
                    return;
                }
                assert!(
                    stats.running,
                    "forwarder stopped before capturing the expected packets: {stats:?}"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("capture tap did not publish the expected packet samples");
    }

    #[cfg(target_os = "linux")]
    fn tcp_packet(
        port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        fn checksum(bytes: &[u8]) -> u16 {
            let mut sum = bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32)
                .sum::<u32>();
            while sum > 65535 {
                sum = (sum & 65535) + (sum >> 16);
            }
            !(sum as u16)
        }
        let mut packet = vec![0u8; 40 + payload.len()];
        let length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 44, 0, 2]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let ip_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet[20..22].copy_from_slice(&45001u16.to_be_bytes());
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[28..32].copy_from_slice(&acknowledgement.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&65535u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let mut pseudoheader = packet[12..20].to_vec();
        pseudoheader.extend_from_slice(&[0, 6]);
        pseudoheader.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pseudoheader.extend_from_slice(&packet[20..]);
        packet[36..38].copy_from_slice(&checksum(&pseudoheader).to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn tap_preserves_traffic_and_bounds_capture_memory() {
        let generation = {
            let mut capture = locked();
            capture.generation = capture.generation.wrapping_add(1);
            capture.stats = CaptureStats {
                running: true,
                ..Default::default()
            };
            capture.packets.clear();
            capture.generation
        };
        let (local, mut peer) = tokio::io::duplex(128);
        let mut tap = TapDevice {
            inner: local,
            generation,
        };
        peer.write_all(b"outgoing").await.unwrap();
        let mut packet = [0; 8];
        tap.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"outgoing");
        tap.write_all(b"incoming").await.unwrap();
        peer.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"incoming");
        let (captured, stats) = drain();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].data, b"outgoing");
        assert_eq!(captured[1].data, b"incoming");
        assert_eq!(stats.received_bytes, 16);
        assert_eq!(stats.queued_bytes, 0);

        let large_packet = vec![0; 65535];
        for _ in 0..200 {
            sample(generation, &large_packet);
        }
        let stats = status();
        assert!(stats.queued_bytes <= MAX_QUEUE_BYTES);
        assert!(stats.queued_packets <= MAX_QUEUE_PACKETS);
        assert!(stats.dropped_packets > 0);
        // Overflow only drops samples: forwarding still succeeds.
        tap.write_all(b"incoming").await.unwrap();
        peer.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet, b"incoming");
        finish(generation, None);
        assert!(!status().running);

        #[cfg(target_os = "linux")]
        {
            use std::os::{fd::IntoRawFd, unix::net::UnixDatagram};
            // A Unix datagram pair supplies packet boundaries like Android's
            // TUN. This exercises the real userspace forwarding stack without
            // root privileges, an emulator, or a network connection.
            let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let port = echo.local_addr().unwrap().port();
            let (tun, kernel) = UnixDatagram::pair().unwrap();
            kernel
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let fd = tun.into_raw_fd();
            start(fd).unwrap();
            assert!(status().running);

            let payload = b"seekershark-forwarding-check";
            let length = (20 + 8 + payload.len()) as u16;
            let udp_length = (8 + payload.len()) as u16;
            let mut ip = vec![0u8; usize::from(length)];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&length.to_be_bytes());
            ip[8] = 64;
            ip[9] = 17;
            ip[12..16].copy_from_slice(&[10, 44, 0, 2]);
            ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
            let mut sum = ip[..20]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
                .sum::<u32>();
            while sum > 65535 {
                sum = (sum & 65535) + (sum >> 16);
            }
            ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            ip[20..22].copy_from_slice(&45000u16.to_be_bytes());
            ip[22..24].copy_from_slice(&port.to_be_bytes());
            ip[24..26].copy_from_slice(&udp_length.to_be_bytes());
            ip[28..].copy_from_slice(payload);
            kernel.send(&ip).unwrap();

            let mut datagram = [0u8; 2048];
            let (received, sender) = echo.recv_from(&mut datagram).unwrap();
            assert_eq!(&datagram[..received], payload);
            echo.send_to(&datagram[..received], sender).unwrap();
            let received = kernel.recv(&mut datagram).unwrap();
            assert_eq!(&datagram[28..received], payload);
            // poll_write publishes its capture sample after the underlying
            // write. The receiver can therefore observe the reply before the
            // forwarding worker has appended that sample to the queue.
            wait_for_samples(2).await;
            let (captured, stats) = drain();
            assert_eq!(captured.len(), 2);
            assert_eq!(stats.dropped_packets, 0);

            // Exercise actual TCP termination/forwarding as well as UDP: raw
            // SYN/ACK/data on the TUN side, an ordinary TcpStream on the server
            // side, then raw TCP response data and its acknowledgement.
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let client_sequence = 12346u32;
            kernel
                .send(&tcp_packet(port, client_sequence - 1, 0, 0x02, &[]))
                .unwrap();
            let received = kernel.recv(&mut datagram).unwrap();
            assert!(received >= 40);
            assert_eq!(datagram[9], 6);
            let ip_header = usize::from(datagram[0] & 0x0f) * 4;
            let tcp = &datagram[ip_header..received];
            assert_eq!(tcp[13] & 0x12, 0x12, "expected SYN/ACK");
            assert_eq!(
                u32::from_be_bytes(tcp[8..12].try_into().unwrap()),
                client_sequence
            );
            let mut server_sequence =
                u32::from_be_bytes(tcp[4..8].try_into().unwrap()).wrapping_add(1);
            kernel
                .send(&tcp_packet(
                    port,
                    client_sequence,
                    server_sequence,
                    0x10,
                    &[],
                ))
                .unwrap();
            let payload = b"seekershark-real-tcp-roundtrip";
            kernel
                .send(&tcp_packet(
                    port,
                    client_sequence,
                    server_sequence,
                    0x18,
                    payload,
                ))
                .unwrap();

            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut echo = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "forwarder did not open the real TCP socket"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("TCP accept failed: {error}"),
                }
            };
            echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            echo.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut observed = vec![0; payload.len()];
            echo.read_exact(&mut observed).unwrap();
            assert_eq!(observed, payload);
            echo.write_all(&observed).unwrap();

            let mut returned = Vec::new();
            while returned.len() < payload.len() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "TCP response did not reach the TUN"
                );
                let received = kernel.recv(&mut datagram).unwrap();
                let ip_header = usize::from(datagram[0] & 0x0f) * 4;
                let tcp = &datagram[ip_header..received];
                let tcp_header = usize::from(tcp[12] >> 4) * 4;
                let data = &tcp[tcp_header..];
                if data.is_empty() {
                    continue;
                }
                assert_eq!(
                    u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
                    server_sequence
                );
                returned.extend_from_slice(data);
                server_sequence = server_sequence.wrapping_add(data.len() as u32);
                kernel
                    .send(&tcp_packet(
                        port,
                        client_sequence + payload.len() as u32,
                        server_sequence,
                        0x10,
                        &[],
                    ))
                    .unwrap();
            }
            assert_eq!(returned, payload);
            stop();
            assert!(!status().running);
            assert!(std::fs::metadata(format!("/proc/self/fd/{fd}")).is_err());
            let (captured, stats) = drain();
            assert!(captured.len() >= 5);
            assert_eq!(stats.dropped_packets, 0);
        }
    }
}
