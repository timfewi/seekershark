import { invoke, isTauri } from '@tauri-apps/api/core';

export interface Field { name: string; value: string }
export interface Layer { name: string; fields: Field[] }
export interface Packet {
  id: number; timestamp: number; source: string; destination: string;
  sourcePort: number | null; destinationPort: number | null;
  protocol: string; length: number; info: string; layers: Layer[]; hex: string;
  capturedLength?: number; truncated?: boolean;
}
export interface Capture {
  packets: Packet[]; totalPackets: number; totalBytes: number;
  droppedPackets: number; linkType: number;
}
export const isNative = () => isTauri();
export const emptyCapture = (): Capture => ({ packets: [], totalPackets: 0, totalBytes: 0, droppedPackets: 0, linkType: 101 });
export const snapshot = () => invoke<Capture>('capture_snapshot');
export const clearCapture = () => invoke<void>('clear_capture');
export const packetDetail = (id: number) => invoke<Packet>('packet_detail', { id });
export interface CaptureStatus { running: boolean; lastError?: string | null; receivedPackets: number; receivedBytes: number; droppedPackets: number; queuedPackets: number; queuedBytes: number }
export const captureStatus = () => invoke<CaptureStatus>('capture_status');
export const startCapture = () => invoke<CaptureStatus>('capture_start');
export const stopCapture = () => invoke<CaptureStatus>('capture_stop');
export const importPcap = async (file: File) => {
  if (!isNative()) throw new Error('PCAP import requires the Android app.');
  const data = new Uint8Array(await file.arrayBuffer());
  return invoke<Capture>('import_pcap', data);
};
export const exportPcap = () => invoke<number[]>('export_pcap');
export const savePcap = () => invoke<string>('save_pcap');
export const savePcapData = (data: Uint8Array) => invoke<string>('save_pcap_data', { data: Array.from(data) });

export interface ScanRequest {
  target: string; ports: string; concurrency: number; timeoutMs: number;
  serviceDetection: boolean; probeTimeoutMs: number;
}
export interface ScanResult {
  address: string; port: number; connectMs: number; service: string;
  evidence: 'port' | 'response' | 'none'; portHint: string | null; product: string; banner: string;
}
export interface ScanSnapshot {
  id: number; phase: 'idle' | 'resolving' | 'running' | 'cancelling' | 'completed' | 'cancelled' | 'failed';
  request: ScanRequest | null; addresses: string[]; portCount: number; total: number; completed: number;
  open: number; closed: number; timedOut: number; errors: number; resultsRetained: number;
  resultsDropped: number; results: ScanResult[]; startedAt: number; elapsedMs: number; error: string | null;
}
export const scanStatus = (limit = 150) => invoke<ScanSnapshot>('scan_status', { limit });
export const scanStart = (request: ScanRequest) => invoke<ScanSnapshot>('scan_start', { request });
export const scanStop = () => invoke<ScanSnapshot>('scan_stop');
export const scanExport = () => invoke<string>('scan_export');
export const emptyScan = (): ScanSnapshot => ({ id: 0, phase: 'idle', request: null, addresses: [], portCount: 0, total: 0, completed: 0, open: 0, closed: 0, timedOut: 0, errors: 0, resultsRetained: 0, resultsDropped: 0, results: [], startedAt: 0, elapsedMs: 0, error: null });

export interface NearbyPeer {
  id: string; name: string; state: 'found' | 'connecting' | 'confirming' | 'connected';
  authenticationCode: string | null;
}
export interface NearbyTransfer {
  id: string; peerName: string; name: string; bytes: number; totalBytes: number;
  state: 'sending' | 'receiving' | 'received' | 'sent' | 'failed'; error: string | null;
}
export interface NearbySnapshot {
  supported: boolean; active: boolean; name: string;
  peers: NearbyPeer[]; transfers: NearbyTransfer[]; lastError: string | null;
}
export const emptyNearby = (supported = false): NearbySnapshot => ({ supported, active: false, name: '', peers: [], transfers: [], lastError: null });
export const nearbyStatus = () => invoke<NearbySnapshot>('nearby_status');
export const nearbyStart = (name: string) => invoke<NearbySnapshot>('nearby_start', { name });
export const nearbyStop = () => invoke<NearbySnapshot>('nearby_stop');
export const nearbyConnect = (endpointId: string) => invoke<NearbySnapshot>('nearby_connect', { endpointId });
export const nearbyConfirm = (endpointId: string, accept: boolean) => invoke<NearbySnapshot>('nearby_confirm', { endpointId, accept });
export const nearbyDisconnect = (endpointId: string) => invoke<NearbySnapshot>('nearby_disconnect', { endpointId });
export const nearbyShare = (endpointId: string) => invoke<NearbySnapshot>('nearby_share', { endpointId });
export const nearbyImport = (id: string) => invoke<{ capture: Capture; name: string; peerName: string }>('nearby_import', { id });
export const nearbyDiscard = (id: string) => invoke<NearbySnapshot>('nearby_discard', { id });

export interface BleObservation {
  id: string; address: string; name: string | null; rssi: number; txPower: number | null;
  connectable: boolean; legacy: boolean; primaryPhy: number; secondaryPhy: number;
  advertisingSid: number | null; manufacturerIds: number[]; serviceUuids: string[];
  advertisementHex: string; payloadTruncated: boolean; firstSeen: number; lastSeen: number; advertisements: number;
}
export interface BleSnapshot {
  supported: boolean; active: boolean; startedAt: number | null; elapsedMs: number; durationSeconds: number;
  advertisements: number; droppedObservations: number; maxObservations: number;
  observations: BleObservation[]; lastError: string | null;
}
export const emptyBle = (supported = false): BleSnapshot => ({ supported, active: false, startedAt: null, elapsedMs: 0, durationSeconds: 60, advertisements: 0, droppedObservations: 0, maxObservations: 256, observations: [], lastError: null });
export const bleStatus = () => invoke<BleSnapshot>('ble_status');
export const bleStart = (durationSeconds: number) => invoke<BleSnapshot>('ble_start', { durationSeconds });
export const bleStop = () => invoke<BleSnapshot>('ble_stop');
export const bleClear = () => invoke<BleSnapshot>('ble_clear');
export const bleExport = () => invoke<string>('ble_export');

export interface WifiSensorReport {
  schemaVersion: 1; source: 'external-wifi-sensor';
  sensor: { id: string; label: string; adapter: string; driver: string; bands: Array<'2.4GHz' | '5GHz' | '6GHz'>; channels: number[] };
  startedAt: number; endedAt: number;
  observations: Array<{ transmitter: string; firstSeen: number; lastSeen: number; frames: number; rssiDbm: number | null; channel: number; frequencyMhz: number; frameTypes: string[] }>;
}
export interface WifiSensorSnapshot {
  schemaVersion: 1; transport: 'report-import'; liveSupported: false; report: WifiSensorReport | null; lastError: string | null;
}
export const emptyWifiSensor = (): WifiSensorSnapshot => ({ schemaVersion: 1, transport: 'report-import', liveSupported: false, report: null, lastError: null });
export const wifiSensorStatus = () => invoke<WifiSensorSnapshot>('wifi_sensor_status');
export const wifiSensorClear = () => invoke<WifiSensorSnapshot>('wifi_sensor_clear');
export const wifiSensorExport = () => invoke<string>('wifi_sensor_export');
export const wifiSensorImport = async (file: File) => {
  if (!isNative()) throw new Error('Sensor report import requires the Android app.');
  if (file.size > 1024 * 1024) throw new Error('Sensor report limit: 1 MiB.');
  return invoke<WifiSensorSnapshot>('wifi_sensor_import', new Uint8Array(await file.arrayBuffer()));
};

export function saveFile(data: Uint8Array, name: string, type = 'application/vnd.tcpdump.pcap') {
  const blob = new Blob([data as BlobPart], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
