use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

mod models;
pub use models::*;

#[cfg(target_os = "android")]
mod forwarder;

pub struct Capture<R: Runtime> {
    #[cfg(target_os = "android")]
    handle: tauri::plugin::PluginHandle<R>,
    #[cfg(not(target_os = "android"))]
    _runtime: std::marker::PhantomData<R>,
}

impl<R: Runtime> Capture<R> {
    pub fn ble_start(&self, duration_seconds: u32) -> Result<BleSnapshot, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Options {
            duration_seconds: u32,
        }
        if !(10..=120).contains(&duration_seconds) {
            return Err("BLE scan duration must be between 10 and 120 seconds.".into());
        }
        self.ble_call("bleStart", Options { duration_seconds })
    }

    pub fn ble_status(&self) -> Result<BleSnapshot, String> {
        #[cfg(target_os = "android")]
        {
            self.ble_call("bleStatus", ())
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(BleSnapshot::default())
        }
    }

    pub fn ble_stop(&self) -> Result<BleSnapshot, String> {
        self.ble_call("bleStop", ())
    }

    pub fn ble_clear(&self) -> Result<BleSnapshot, String> {
        self.ble_call("bleClear", ())
    }

    // BLE uses Android's scanner directly and does not require Google services.
    // Like Nearby and VPN, plugin callbacks may wait for Android permission UI.
    fn ble_call<T: serde::de::DeserializeOwned>(
        &self,
        command: &str,
        payload: impl Serialize,
    ) -> Result<T, String> {
        #[cfg(target_os = "android")]
        {
            self.handle
                .run_mobile_plugin(command, payload)
                .map_err(|error| error.to_string())
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (command, payload);
            Err("BLE scanning requires the Android app and Bluetooth LE hardware.".into())
        }
    }

    /// Nearby calls may wait for an Android permission or task callback. Call
    /// every method from a blocking worker, never the renderer or async worker.
    fn nearby_call<T: serde::de::DeserializeOwned>(
        &self,
        command: &str,
        payload: impl Serialize,
    ) -> Result<T, String> {
        #[cfg(target_os = "android")]
        {
            self.handle
                .run_mobile_plugin(command, payload)
                .map_err(|error| error.to_string())
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (command, payload);
            Err("Nearby requires the Android app with Google Play services.".into())
        }
    }

    pub fn nearby_status(&self) -> Result<NearbySnapshot, String> {
        #[cfg(target_os = "android")]
        {
            self.nearby_call("nearbyStatus", ())
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(NearbySnapshot::default())
        }
    }

    pub fn nearby_start(&self, name: String) -> Result<NearbySnapshot, String> {
        #[derive(Serialize)]
        struct Options {
            name: String,
        }
        let name = name.trim().to_owned();
        validate_nearby_text(&name, 32, "Device name")?;
        if name.len() > 128 {
            return Err("Device name exceeds 128 UTF-8 bytes.".into());
        }
        self.nearby_call("nearbyStart", Options { name })
    }

    pub fn nearby_stop(&self) -> Result<NearbySnapshot, String> {
        self.nearby_call("nearbyStop", ())
    }

    pub fn nearby_connect(&self, endpoint_id: String) -> Result<NearbySnapshot, String> {
        validate_nearby_text(&endpoint_id, 128, "Endpoint ID")?;
        self.nearby_call("nearbyConnect", EndpointOptions { endpoint_id })
    }

    pub fn nearby_confirm(
        &self,
        endpoint_id: String,
        accept: bool,
    ) -> Result<NearbySnapshot, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Options {
            endpoint_id: String,
            accept: bool,
        }
        validate_nearby_text(&endpoint_id, 128, "Endpoint ID")?;
        self.nearby_call(
            "nearbyConfirm",
            Options {
                endpoint_id,
                accept,
            },
        )
    }

    pub fn nearby_disconnect(&self, endpoint_id: String) -> Result<NearbySnapshot, String> {
        validate_nearby_text(&endpoint_id, 128, "Endpoint ID")?;
        self.nearby_call("nearbyDisconnect", EndpointOptions { endpoint_id })
    }

    pub fn nearby_send_capture(
        &self,
        endpoint_id: String,
        data: Vec<u8>,
        name: String,
    ) -> Result<NearbySnapshot, String> {
        use base64::Engine;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Options {
            endpoint_id: String,
            name: String,
            data_base64: String,
        }
        validate_nearby_text(&endpoint_id, 128, "Endpoint ID")?;
        validate_nearby_text(&name, 120, "Capture name")?;
        if data.len() > MAX_NEARBY_CAPTURE_BYTES {
            return Err("Nearby capture exceeds 40 MiB.".into());
        }
        self.nearby_call(
            "nearbySendCapture",
            Options {
                endpoint_id,
                name,
                data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            },
        )
    }

    pub fn nearby_read_capture(&self, id: String) -> Result<NearbyCapture, String> {
        validate_nearby_text(&id, 128, "Transfer ID")?;
        let received: NearbyCapturePayload =
            self.nearby_call("nearbyReadCapture", TransferOptions { id })?;
        decode_nearby_capture(received)
    }

    pub fn nearby_discard_capture(&self, id: String) -> Result<NearbySnapshot, String> {
        validate_nearby_text(&id, 128, "Transfer ID")?;
        self.nearby_call("nearbyDiscardCapture", TransferOptions { id })
    }

    /// Opens Android's VPN consent dialog, then starts local forwarding/capture.
    /// This waits for the native response; invoke from a blocking worker thread.
    pub fn start(&self) -> Result<CaptureStatus, String> {
        #[cfg(target_os = "android")]
        {
            self.handle
                .run_mobile_plugin("startCapture", ())
                .map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "android"))]
        {
            Err(
                "Live capture requires the Android app. Import a PCAP file on this platform."
                    .into(),
            )
        }
    }

    pub fn stop(&self) -> Result<CaptureStatus, String> {
        #[cfg(target_os = "android")]
        {
            self.handle
                .run_mobile_plugin("stopCapture", ())
                .map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(CaptureStats::default())
        }
    }

    pub fn status(&self) -> Result<CaptureStatus, String> {
        #[cfg(target_os = "android")]
        {
            self.handle
                .run_mobile_plugin("captureStatus", ())
                .map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(CaptureStats::default())
        }
    }

    /// Save an explicit user-requested export to Android Downloads/SeekerShark.
    /// Returns a content URI on API 29+, or an app-scoped file path on API 24–28.
    pub fn save_pcap(&self, data: Vec<u8>, name: String) -> Result<String, String> {
        self.save_export(data, name, false)
    }

    pub fn save_report(&self, data: Vec<u8>, name: String) -> Result<String, String> {
        self.save_export(data, name, true)
    }

    fn save_export(&self, data: Vec<u8>, name: String, report: bool) -> Result<String, String> {
        #[cfg(target_os = "android")]
        {
            use base64::Engine;
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct ExportPayload {
                data_base64: String,
                name: String,
            }
            #[derive(Deserialize)]
            struct ExportResult {
                uri: String,
            }
            // Include record headers above the app's 32 MiB packet-byte limit.
            let limit = if report { 8 } else { 40 };
            if data.len() > limit * 1024 * 1024 {
                return Err(format!("Export exceeds {limit} MiB"));
            }
            let result: ExportResult = self
                .handle
                .run_mobile_plugin(
                    if report { "saveReport" } else { "savePcap" },
                    ExportPayload {
                        data_base64: base64::engine::general_purpose::STANDARD.encode(data),
                        name,
                    },
                )
                .map_err(|e| e.to_string())?;
            Ok(result.uri)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (data, name, report);
            Err("Native Downloads export requires Android".into())
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointOptions {
    endpoint_id: String,
}

#[derive(Serialize)]
struct TransferOptions {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NearbyCapturePayload {
    data_base64: String,
    name: String,
    peer_name: String,
}

fn validate_nearby_text(value: &str, limit: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.chars().count() > limit
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain 1–{limit} characters without control characters."
        ));
    }
    Ok(())
}

fn decode_nearby_capture(payload: NearbyCapturePayload) -> Result<NearbyCapture, String> {
    use base64::Engine;
    validate_nearby_text(&payload.name, 120, "Capture name")?;
    validate_nearby_text(&payload.peer_name, 32, "Peer name")?;
    if payload.peer_name.len() > 128 {
        return Err("Peer name exceeds 128 UTF-8 bytes.".into());
    }
    // Bound the encoded input before allocating a second large buffer.
    const MAX_ENCODED: usize = MAX_NEARBY_CAPTURE_BYTES.div_ceil(3) * 4;
    if payload.data_base64.len() > MAX_ENCODED {
        return Err("Nearby capture exceeds 40 MiB.".into());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(payload.data_base64)
        .map_err(|_| "Nearby capture contains invalid base64 data.".to_owned())?;
    if data.len() > MAX_NEARBY_CAPTURE_BYTES {
        return Err("Nearby capture exceeds 40 MiB.".into());
    }
    Ok(NearbyCapture {
        data,
        name: payload.name,
        peer_name: payload.peer_name,
    })
}

#[cfg(test)]
mod nearby_tests {
    use super::*;

    #[test]
    fn names_allow_unicode_but_reject_controls_and_excess_length() {
        assert!(validate_nearby_text("Tims Seeker 📱", 32, "Name").is_ok());
        for value in [" ", "Phone\nspoof", "\0"] {
            assert!(validate_nearby_text(value, 32, "Name").is_err());
        }
        assert!(validate_nearby_text(&"a".repeat(33), 32, "Name").is_err());
    }

    #[test]
    fn native_received_data_is_validated_before_use() {
        let make = |data: &str| NearbyCapturePayload {
            data_base64: data.into(),
            name: "capture.pcap".into(),
            peer_name: "Seeker".into(),
        };
        assert_eq!(decode_nearby_capture(make("AQID")).unwrap().data, [1, 2, 3]);
        assert!(decode_nearby_capture(make("not base64!")).is_err());
        assert!(decode_nearby_capture(NearbyCapturePayload {
            peer_name: "untrusted\npeer".into(),
            ..make("AQID")
        })
        .is_err());
    }

    #[test]
    fn unknown_native_states_cannot_appear_as_confirmed_peers() {
        let peer = r#"{"id":"p","name":"Phone","state":"connected","authenticationCode":null}"#;
        assert_eq!(
            serde_json::from_str::<NearbyPeer>(peer).unwrap().state,
            NearbyPeerState::Connected
        );
        assert!(serde_json::from_str::<NearbyPeer>(&peer.replace("connected", "trusted")).is_err());
        let status = serde_json::to_value(NearbySnapshot::default()).unwrap();
        assert_eq!(status["supported"], false);
        assert!(status.get("lastError").is_some());
    }
}

pub trait CaptureExt<R: Runtime> {
    fn capture(&self) -> &Capture<R>;
}

impl<R: Runtime, T: Manager<R>> CaptureExt<R> for T {
    fn capture(&self) -> &Capture<R> {
        self.state::<Capture<R>>().inner()
    }
}

/// Drains the bounded native queue. Poll at 100–250 ms and batch frontend updates.
pub fn drain() -> (Vec<RawPacket>, CaptureStats) {
    #[cfg(target_os = "android")]
    {
        forwarder::drain()
    }
    #[cfg(not(target_os = "android"))]
    {
        (Vec::new(), CaptureStats::default())
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("capture")
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            forwarder::ensure_linked();
            #[cfg(target_os = "android")]
            let capture = Capture {
                handle: _api.register_android_plugin("dev.seekershark.capture", "CapturePlugin")?,
            };
            #[cfg(not(target_os = "android"))]
            let capture = Capture {
                _runtime: std::marker::PhantomData::<R>,
            };
            app.manage(capture);
            Ok(())
        })
        .build()
}
