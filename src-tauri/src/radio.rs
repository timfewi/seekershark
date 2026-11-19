use radio_engine::{WifiSensorStatus, WifiSensorStore, MAX_REPORT_BYTES};
use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_capture::{BleSnapshot, CaptureExt};

#[derive(Default)]
pub struct RadioState(Mutex<WifiSensorStore>);

#[tauri::command]
pub async fn ble_start(
    duration_seconds: u32,
    app: tauri::AppHandle,
) -> Result<BleSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().ble_start(duration_seconds))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn ble_status(app: tauri::AppHandle) -> Result<BleSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().ble_status())
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn ble_stop(app: tauri::AppHandle) -> Result<BleSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().ble_stop())
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn ble_clear(app: tauri::AppHandle) -> Result<BleSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || app.capture().ble_clear())
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn ble_export(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = app.capture().ble_status()?;
        if report.started_at.is_none() {
            return Err("There is no BLE scan report to export.".into());
        }
        let name = format!("seekershark-ble-{}.json", report.started_at.unwrap_or(0));
        let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
        app.capture().save_report(bytes, name)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn wifi_sensor_status(app: tauri::AppHandle) -> Result<WifiSensorStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<RadioState>();
        let store = state
            .0
            .lock()
            .map_err(|_| "Wi-Fi sensor state unavailable")?;
        Ok(store.status())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn wifi_sensor_import(
    request: tauri::ipc::Request<'_>,
    app: tauri::AppHandle,
) -> Result<WifiSensorStatus, String> {
    let bytes = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes,
        _ => return Err("Wi-Fi sensor import requires binary JSON file data.".into()),
    };
    if bytes.len() > MAX_REPORT_BYTES {
        return Err("Wi-Fi sensor report exceeds 1 MiB.".into());
    }
    let data = bytes.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<RadioState>();
        let mut store = state
            .0
            .lock()
            .map_err(|_| "Wi-Fi sensor state unavailable")?;
        store.import(&data)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn wifi_sensor_clear(app: tauri::AppHandle) -> Result<WifiSensorStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<RadioState>();
        let mut store = state
            .0
            .lock()
            .map_err(|_| "Wi-Fi sensor state unavailable")?;
        Ok(store.clear())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn wifi_sensor_export(app: tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // Keep sensor reports independent from VPN captures and release the
        // state lock before Android handles the user-requested Downloads write.
        let (bytes, started_at) = {
            let state = app.state::<RadioState>();
            let store = state
                .0
                .lock()
                .map_err(|_| "Wi-Fi sensor state unavailable")?;
            let report = store.status();
            let started_at = report
                .report
                .as_ref()
                .ok_or("There is no Wi-Fi sensor report to export.")?
                .started_at;
            (store.export()?, started_at)
        };
        app.capture()
            .save_report(bytes, format!("seekershark-wifi-sensor-{started_at}.json"))
    })
    .await
    .map_err(|error| error.to_string())?
}
