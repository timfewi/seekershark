use packet_engine::{Capture, Packet, PacketStore, LINKTYPE_RAW, MAX_IMPORT_SIZE};
use scan_engine::{ScanRequest, ScanSnapshot, Scanner, MAX_RESULTS};
use std::sync::Mutex;
use tauri::{Manager, State};
use tauri_plugin_capture::{CaptureExt, CaptureStatus, NearbySnapshot};

mod radio;

const RETAIN_PACKETS: usize = 10_000;
const RETAIN_BYTES: usize = 32 * 1024 * 1024;
const WINDOW_PACKETS: usize = 1_500;

struct Session {
    store: PacketStore,
    live: bool,
    starting: bool,
    queue_drops: u64,
}
struct Analysis(Mutex<Session>);

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct NearbyImport {
    capture: Capture,
    name: String,
    peer_name: String,
}

#[tauri::command]
async fn nearby_status(app: tauri::AppHandle) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_status())
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_start(name: String, app: tauri::AppHandle) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_start(name))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_stop(app: tauri::AppHandle) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_stop())
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_connect(
    endpoint_id: String,
    app: tauri::AppHandle,
) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_connect(endpoint_id))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_confirm(
    endpoint_id: String,
    accept: bool,
    app: tauri::AppHandle,
) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_confirm(endpoint_id, accept))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_disconnect(
    endpoint_id: String,
    app: tauri::AppHandle,
) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_disconnect(endpoint_id))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_share(
    endpoint_id: String,
    app: tauri::AppHandle,
) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // Export a consistent snapshot, then release the store while Android
        // handles transfer setup. This shares neither future packets nor a stream.
        let data = {
            let state = app.state::<Analysis>();
            let session = state.0.lock().map_err(|_| "Capture state unavailable")?;
            if session.store.snapshot(0, 0).total_packets == 0 {
                return Err("There are no captured packets to share.".into());
            }
            session
                .store
                .export_pcap()
                .map_err(|error| error.to_string())?
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        app.capture()
            .nearby_send_capture(endpoint_id, data, format!("seekershark-{stamp}.pcap"))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_import(id: String, app: tauri::AppHandle) -> Result<NearbyImport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        {
            let state = app.state::<Analysis>();
            let session = state.0.lock().map_err(|_| "Capture state unavailable")?;
            ensure_import_idle(&session)?;
        }
        // Incoming bytes remain untrusted even after authenticated pairing.
        // Native returns an opaque inbox entry, never a caller-provided path.
        let received = app.capture().nearby_read_capture(id.clone())?;
        let store =
            PacketStore::import_pcap(&received.data, RETAIN_PACKETS, RETAIN_BYTES, 1_000_000)
                .map_err(|error| error.to_string())?;
        let capture = {
            let state = app.state::<Analysis>();
            let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
            // Starting capture can race with the Android read; check again
            // before replacing anything. A failed import preserves the inbox.
            install_nearby_capture(&mut session, store)?
        };
        // An unavailable cleanup callback must not turn a successful import
        // into an error after the user's analysis has already been replaced.
        let _ = app.capture().nearby_discard_capture(id);
        Ok(NearbyImport {
            capture,
            name: received.name,
            peer_name: received.peer_name,
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn nearby_discard(id: String, app: tauri::AppHandle) -> Result<NearbySnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().nearby_discard_capture(id))
        .await
        .map_err(|error| error.to_string())?
}

fn ensure_import_idle(session: &Session) -> Result<(), String> {
    if session.live || session.starting {
        return Err("Stop the current capture before opening a received capture.".into());
    }
    Ok(())
}

fn install_nearby_capture(session: &mut Session, store: PacketStore) -> Result<Capture, String> {
    ensure_import_idle(session)?;
    session.store = store;
    session.queue_drops = 0;
    Ok(window(session))
}

#[tauri::command]
async fn scan_start(
    request: ScanRequest,
    state: State<'_, Scanner>,
) -> Result<ScanSnapshot, String> {
    state.start(request)
}

#[tauri::command]
fn scan_status(limit: Option<usize>, state: State<'_, Scanner>) -> Result<ScanSnapshot, String> {
    state.snapshot(limit.unwrap_or(150))
}

#[tauri::command]
fn scan_stop(state: State<'_, Scanner>) -> Result<ScanSnapshot, String> {
    state.stop()
}

#[tauri::command]
async fn scan_export(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = app.state::<Scanner>().snapshot(MAX_RESULTS)?;
        if report.id == 0 {
            return Err("There is no scan report to export.".into());
        }
        let name = format!("seekershark-scan-{}.json", report.started_at);
        let data = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
        app.capture().save_report(data, name)
    })
    .await
    .map_err(|error| error.to_string())?
}

fn window(session: &Session) -> Capture {
    let total = session.store.snapshot(u64::MAX, 0).total_packets;
    let limit = if session.live {
        WINDOW_PACKETS
    } else {
        RETAIN_PACKETS
    };
    let mut capture = session
        .store
        .snapshot(total.saturating_sub(limit as u64), limit);
    capture.dropped_packets = capture.dropped_packets.saturating_add(session.queue_drops);
    capture
}

#[tauri::command]
fn capture_snapshot(state: State<'_, Analysis>) -> Result<Capture, String> {
    let session = state.0.lock().map_err(|_| "Capture state unavailable")?;
    Ok(window(&session))
}

#[tauri::command]
fn packet_detail(id: u64, state: State<'_, Analysis>) -> Result<Packet, String> {
    state
        .0
        .lock()
        .map_err(|_| "Capture state unavailable")?
        .store
        .packet_detail(id)
        .ok_or_else(|| "This packet is no longer in the capture buffer.".into())
}

#[tauri::command]
fn clear_capture(state: State<'_, Analysis>) -> Result<(), String> {
    let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
    session.store.clear();
    session.queue_drops = 0;
    Ok(())
}

#[tauri::command]
async fn capture_start(app: tauri::AppHandle) -> Result<CaptureStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        {
            let state = app.state::<Analysis>();
            let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
            if session.live || session.starting {
                return Err("A capture is already running.".into());
            }
            session.starting = true;
        }
        let result = app.capture().start();
        {
            let state = app.state::<Analysis>();
            let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
            session.starting = false;
            if result.is_ok() {
                // Preserve the old analysis when consent is denied. Once started,
                // never mix live raw IP packets into an imported Ethernet capture.
                session.store = PacketStore::new(RETAIN_PACKETS, RETAIN_BYTES, LINKTYPE_RAW)
                    .map_err(|e| e.to_string())?;
                session.queue_drops = 0;
                session.live = true;
            }
        }
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn capture_stop(app: tauri::AppHandle) -> Result<CaptureStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let result = app.capture().stop();
        let state = app.state::<Analysis>();
        let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
        if session.live {
            loop {
                let (packets, stats) = tauri_plugin_capture::drain();
                for packet in packets {
                    let _ = session.store.ingest(
                        packet.timestamp,
                        &packet.data,
                        packet.data.len() as u32,
                    );
                }
                session.queue_drops = stats.dropped_packets;
                if stats.queued_packets == 0 {
                    break;
                }
            }
            session.live = false;
        }
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn capture_status(app: tauri::AppHandle) -> Result<CaptureStatus, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().status())
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn import_pcap(
    request: tauri::ipc::Request<'_>,
    app: tauri::AppHandle,
) -> Result<Capture, String> {
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes,
        _ => return Err("PCAP import requires binary file data.".into()),
    };
    if bytes.len() > MAX_IMPORT_SIZE {
        return Err("PCAP file exceeds 64 MiB.".into());
    }
    let data = bytes.clone();
    if data.len() > MAX_IMPORT_SIZE {
        return Err("PCAP file exceeds 64 MiB.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        // Parse first; an invalid import leaves the current capture intact.
        let store = PacketStore::import_pcap(&data, RETAIN_PACKETS, RETAIN_BYTES, 1_000_000)
            .map_err(|e| e.to_string())?;
        let state = app.state::<Analysis>();
        let mut session = state.0.lock().map_err(|_| "Capture state unavailable")?;
        if session.live || session.starting {
            return Err("Stop the current capture before importing.".into());
        }
        session.store = store;
        session.queue_drops = 0;
        Ok(window(&session))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn export_pcap(state: State<'_, Analysis>) -> Result<Vec<u8>, String> {
    state
        .0
        .lock()
        .map_err(|_| "Capture state unavailable")?
        .store
        .export_pcap()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_pcap(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = app
            .state::<Analysis>()
            .0
            .lock()
            .map_err(|_| "Capture state unavailable")?
            .store
            .export_pcap()
            .map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        app.capture()
            .save_pcap(data, format!("seekershark-{stamp}.pcap"))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn save_pcap_data(data: Vec<u8>, app: tauri::AppHandle) -> Result<String, String> {
    if data.len() > 32 * 1024 * 1024 {
        return Err("PCAP export exceeds 32 MiB.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        app.capture()
            .save_pcap(data, "seekershark-demo.pcap".into())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_capture::init())
        .manage(Scanner::default())
        .manage(radio::RadioState::default())
        .manage(Analysis(Mutex::new(Session {
            store: PacketStore::new(RETAIN_PACKETS, RETAIN_BYTES, LINKTYPE_RAW)
                .expect("valid retention settings"),
            live: false,
            starting: false,
            queue_drops: 0,
        })))
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("packet-analysis".into())
                .spawn(move || loop {
                    let mut backlog = false;
                    if let Ok(mut session) = handle.state::<Analysis>().0.lock() {
                        if session.live && !session.starting {
                            let (packets, stats) = tauri_plugin_capture::drain();
                            backlog = stats.queued_packets > 0;
                            for packet in packets {
                                let _ = session.store.ingest(
                                    packet.timestamp,
                                    &packet.data,
                                    packet.data.len() as u32,
                                );
                            }
                            session.queue_drops = stats.dropped_packets;
                            if !stats.running && stats.queued_packets == 0 {
                                session.live = false;
                            }
                        }
                    }
                    if backlog {
                        // Drain bursts immediately; sleeping after every 256 packets
                        // would impose an artificial 10k packets/second ceiling.
                        std::thread::yield_now();
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            capture_snapshot,
            packet_detail,
            clear_capture,
            capture_start,
            capture_stop,
            capture_status,
            import_pcap,
            export_pcap,
            save_pcap,
            save_pcap_data,
            scan_start,
            scan_status,
            scan_stop,
            scan_export,
            nearby_status,
            nearby_start,
            nearby_stop,
            nearby_connect,
            nearby_confirm,
            nearby_disconnect,
            nearby_share,
            nearby_import,
            nearby_discard,
            radio::ble_start,
            radio::ble_status,
            radio::ble_stop,
            radio::ble_clear,
            radio::ble_export,
            radio::wifi_sensor_status,
            radio::wifi_sensor_import,
            radio::wifi_sensor_clear,
            radio::wifi_sensor_export
        ])
        .run(tauri::generate_context!())
        .expect("SeekerShark could not start");
}

#[cfg(test)]
mod nearby_tests {
    use super::*;

    fn session() -> Session {
        Session {
            store: PacketStore::new(RETAIN_PACKETS, RETAIN_BYTES, LINKTYPE_RAW).unwrap(),
            live: false,
            starting: false,
            queue_drops: 7,
        }
    }

    #[test]
    fn received_import_never_replaces_a_live_or_starting_capture() {
        for starting in [false, true] {
            let mut current = session();
            current.starting = starting;
            current.live = !starting;
            let received = PacketStore::new(RETAIN_PACKETS, RETAIN_BYTES, 1).unwrap();
            assert!(install_nearby_capture(&mut current, received).is_err());
            assert_eq!(window(&current).link_type, LINKTYPE_RAW);
            assert_eq!(current.queue_drops, 7);
        }
    }

    #[test]
    fn received_capture_keeps_its_linktype_and_resets_local_drop_counts() {
        let mut current = session();
        let received = PacketStore::new(RETAIN_PACKETS, RETAIN_BYTES, 1).unwrap();
        let imported = install_nearby_capture(&mut current, received).unwrap();
        assert_eq!(imported.link_type, 1);
        assert_eq!(imported.dropped_packets, 0);
        assert!(!current.live);
    }
}
