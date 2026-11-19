use serde::{Deserialize, Serialize};

/// Raw IP packets sampled from the VPN, with Unix epoch timestamps in seconds.
/// Data is retained only in a bounded, in-memory queue until drained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {
    pub timestamp: f64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStats {
    pub running: bool,
    pub last_error: Option<String>,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub dropped_packets: u64,
    pub queued_packets: usize,
    pub queued_bytes: usize,
}

pub type CaptureStatus = CaptureStats;

/// Raw BLE scan reports retain advertised data only. Addresses, advertising
/// names and RSSI do not establish a physical-device or phone identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BleObservation {
    pub id: String,
    pub address: String,
    pub name: Option<String>,
    pub rssi: i32,
    pub tx_power: Option<i32>,
    pub connectable: bool,
    pub legacy: bool,
    pub primary_phy: u32,
    pub secondary_phy: u32,
    pub advertising_sid: Option<u32>,
    pub manufacturer_ids: Vec<u32>,
    pub service_uuids: Vec<String>,
    pub advertisement_hex: String,
    pub payload_truncated: bool,
    pub first_seen: u64,
    pub last_seen: u64,
    pub advertisements: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BleSnapshot {
    pub supported: bool,
    pub active: bool,
    pub started_at: Option<u64>,
    pub elapsed_ms: u64,
    pub duration_seconds: u32,
    pub advertisements: u64,
    pub dropped_observations: u64,
    pub max_observations: usize,
    pub observations: Vec<BleObservation>,
    pub last_error: Option<String>,
}

impl Default for BleSnapshot {
    fn default() -> Self {
        Self {
            supported: false,
            active: false,
            started_at: None,
            elapsed_ms: 0,
            duration_seconds: 60,
            advertisements: 0,
            dropped_observations: 0,
            max_observations: 256,
            observations: Vec::new(),
            last_error: None,
        }
    }
}

/// Nearby transfers include PCAP record headers above the packet-byte budget.
pub const MAX_NEARBY_CAPTURE_BYTES: usize = 40 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NearbyPeerState {
    Found,
    Connecting,
    Confirming,
    Connected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbyPeer {
    pub id: String,
    pub name: String,
    pub state: NearbyPeerState,
    pub authentication_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NearbyTransferState {
    Sending,
    Receiving,
    Received,
    Sent,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbyTransfer {
    pub id: String,
    pub peer_name: String,
    pub name: String,
    pub bytes: u64,
    pub total_bytes: u64,
    pub state: NearbyTransferState,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbySnapshot {
    pub supported: bool,
    pub active: bool,
    pub name: String,
    pub peers: Vec<NearbyPeer>,
    pub transfers: Vec<NearbyTransfer>,
    pub last_error: Option<String>,
}

pub struct NearbyCapture {
    pub data: Vec<u8>,
    pub name: String,
    pub peer_name: String,
}
