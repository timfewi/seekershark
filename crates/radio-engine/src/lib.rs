//! Offline metadata import only. This crate opens no sockets or radio devices.
//! An observed transmitter address is not a physical device or phone identity.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_REPORT_BYTES: usize = 1024 * 1024;
pub const MAX_OBSERVATIONS: usize = 2048;
pub const MAX_TIMESTAMP_MS: u64 = 4_102_444_800_000;
/// Tauri sends counters as JSON numbers, which JavaScript represents as f64.
pub const MAX_FRAME_COUNT: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WifiSensorReport {
    pub schema_version: u32,
    pub source: String,
    pub sensor: SensorMetadata,
    /// All report and observation times are integer Unix epoch milliseconds.
    pub started_at: u64,
    pub ended_at: u64,
    pub observations: Vec<WifiObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SensorMetadata {
    pub id: String,
    pub label: String,
    pub adapter: String,
    pub driver: String,
    pub bands: Vec<String>,
    pub channels: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WifiObservation {
    pub transmitter: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub frames: u64,
    pub rssi_dbm: Option<f64>,
    pub channel: u32,
    pub frequency_mhz: u32,
    pub frame_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WifiSensorStatus {
    pub schema_version: u32,
    pub transport: &'static str,
    pub live_supported: bool,
    pub report: Option<WifiSensorReport>,
    pub last_error: Option<String>,
}

/// The only supported transport is an explicitly imported report. A failed
/// import returns its error without altering the previously accepted report.
#[derive(Default)]
pub struct WifiSensorStore {
    report: Option<WifiSensorReport>,
}

impl WifiSensorStore {
    pub fn status(&self) -> WifiSensorStatus {
        WifiSensorStatus {
            schema_version: SCHEMA_VERSION,
            transport: "report-import",
            live_supported: false,
            report: self.report.clone(),
            last_error: None,
        }
    }

    pub fn import(&mut self, bytes: &[u8]) -> Result<WifiSensorStatus, String> {
        let report = parse_report(bytes)?;
        self.report = Some(report);
        Ok(self.status())
    }

    pub fn clear(&mut self) -> WifiSensorStatus {
        self.report = None;
        self.status()
    }

    pub fn export(&self) -> Result<Vec<u8>, String> {
        let report = self
            .report
            .as_ref()
            .ok_or("There is no Wi-Fi sensor report to export.")?;
        serde_json::to_vec(report).map_err(|error| error.to_string())
    }
}

pub fn parse_report(bytes: &[u8]) -> Result<WifiSensorReport, String> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err("Wi-Fi sensor report exceeds 1 MiB.".into());
    }
    let mut report: WifiSensorReport = serde_json::from_slice(bytes)
        .map_err(|error| format!("Invalid Wi-Fi sensor report JSON: {error}"))?;
    if report.schema_version != SCHEMA_VERSION || report.source != "external-wifi-sensor" {
        return Err("Only external-wifi-sensor reports with schemaVersion 1 are supported.".into());
    }
    if report.observations.len() > MAX_OBSERVATIONS {
        return Err("Wi-Fi sensor report exceeds 2,048 transmitter observations.".into());
    }
    validate_times(report.started_at, report.ended_at, "Report")?;
    validate_text(&report.sensor.id, 64, "Sensor ID")?;
    validate_text(&report.sensor.label, 128, "Sensor label")?;
    validate_text(&report.sensor.adapter, 128, "Sensor adapter")?;
    validate_text(&report.sensor.driver, 128, "Sensor driver")?;
    if report.sensor.bands.is_empty() || report.sensor.bands.len() > 3 {
        return Err("Sensor bands must contain 1–3 distinct supported bands.".into());
    }
    let mut bands = HashSet::new();
    for band in &report.sensor.bands {
        if !matches!(band.as_str(), "2.4GHz" | "5GHz" | "6GHz") || !bands.insert(band.as_str()) {
            return Err("Sensor bands must be distinct values from 2.4GHz, 5GHz and 6GHz.".into());
        }
    }
    if report.sensor.channels.is_empty() || report.sensor.channels.len() > 256 {
        return Err("Sensor channels must contain 1–256 distinct channel numbers.".into());
    }
    let mut channels = HashSet::new();
    for &channel in &report.sensor.channels {
        if !channels.insert(channel) || !bands.iter().any(|band| channel_in_band(channel, band)) {
            return Err(
                "Sensor channels must be distinct and compatible with the declared bands.".into(),
            );
        }
    }
    let mut transmitters = HashSet::new();
    for observation in &mut report.observations {
        observation.transmitter = normalize_transmitter(&observation.transmitter)?;
        if !transmitters.insert(observation.transmitter.clone()) {
            return Err("Each observed transmitter address must appear only once.".into());
        }
        validate_times(observation.first_seen, observation.last_seen, "Observation")?;
        if observation.first_seen < report.started_at || observation.last_seen > report.ended_at {
            return Err("Observation timestamps must be within the report interval.".into());
        }
        if observation.frames == 0 || observation.frames > MAX_FRAME_COUNT {
            return Err("Frame count must be an integer from 1 to 9,007,199,254,740,991.".into());
        }
        if observation
            .rssi_dbm
            .is_some_and(|rssi| !rssi.is_finite() || !(-127.0..=20.0).contains(&rssi))
        {
            return Err("RSSI must be null or a finite value between -127 and 20 dBm.".into());
        }
        let band = observation_band(observation.channel, observation.frequency_mhz)
            .ok_or("Observation channel and frequency do not match a supported Wi-Fi band.")?;
        if !bands.contains(band) || !channels.contains(&observation.channel) {
            return Err("Observation band and channel must be declared by the sensor.".into());
        }
        if observation.frame_types.is_empty() || observation.frame_types.len() > 32 {
            return Err("Frame types must contain 1–32 distinct labels.".into());
        }
        let mut frame_types = HashSet::new();
        for frame_type in &observation.frame_types {
            validate_text(frame_type, 48, "Frame type")?;
            if !frame_types.insert(frame_type.as_str()) {
                return Err("Frame type labels must be distinct.".into());
            }
        }
    }
    // Ensure our compact export is itself accepted by the same size limit.
    if serde_json::to_vec(&report)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_REPORT_BYTES
    {
        return Err("Normalized Wi-Fi sensor report exceeds 1 MiB.".into());
    }
    Ok(report)
}

fn validate_text(value: &str, max_chars: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.chars().count() > max_chars
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must contain 1–{max_chars} characters without control characters."
        ));
    }
    Ok(())
}

fn validate_times(first: u64, last: u64, label: &str) -> Result<(), String> {
    if first > last || last > MAX_TIMESTAMP_MS {
        return Err(format!(
            "{label} timestamps must be ordered Unix epoch milliseconds through 2100-01-01."
        ));
    }
    Ok(())
}

fn normalize_transmitter(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    if bytes.len() != 17
        || bytes.iter().enumerate().any(|(index, byte)| {
            if index % 3 == 2 {
                *byte != b':'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err("Transmitter must be a colon-separated six-byte MAC address.".into());
    }
    let first = u8::from_str_radix(&value[..2], 16).map_err(|error| error.to_string())?;
    if first & 1 != 0 || value == "00:00:00:00:00:00" {
        return Err("Transmitter must be a nonzero unicast MAC address.".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn channel_in_band(channel: u32, band: &str) -> bool {
    match band {
        "2.4GHz" => (1..=14).contains(&channel),
        "5GHz" => (32..=177).contains(&channel),
        "6GHz" => (1..=233).contains(&channel),
        _ => false,
    }
}

fn observation_band(channel: u32, frequency: u32) -> Option<&'static str> {
    match channel {
        1..=13 if frequency == 2407 + 5 * channel => Some("2.4GHz"),
        14 if frequency == 2484 => Some("2.4GHz"),
        32..=177 if frequency == 5000 + 5 * channel => Some("5GHz"),
        2 if frequency == 5935 => Some("6GHz"),
        1..=233 if frequency == 5950 + 5 * channel => Some("6GHz"),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
