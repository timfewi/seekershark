import { createEffect, createMemo, createSignal, For, onCleanup, Show } from 'solid-js';
import { bleClear, bleExport, bleStart, bleStatus, bleStop, emptyBle, emptyWifiSensor, wifiSensorClear, wifiSensorExport, wifiSensorImport, wifiSensorStatus, type BleObservation, type BleSnapshot, type WifiSensorSnapshot } from './api';

const number = (value: number) => new Intl.NumberFormat('en-US').format(value);
const time = (value: number) => new Date(value).toLocaleTimeString('en-GB');
const hexId = (value: number) => `0x${value.toString(16).padStart(4, '0')}`;
const phy = (value: number) => ({ 0: 'None', 1: 'LE 1M', 2: 'LE 2M', 3: 'LE Coded' }[value] ?? 'Unknown');

function BleRow(props: { observation: BleObservation }) {
  return <details class="radio-observation" aria-label={`BLE observation ${props.observation.address}`}>
    <summary><span><strong>{props.observation.name || 'Unnamed BLE advertiser'}</strong><code>{props.observation.address}{props.observation.advertisingSid !== null ? ` · SID ${props.observation.advertisingSid}` : ''}</code></span><span class="radio-rssi">{props.observation.rssi} dBm<small>{number(props.observation.advertisements)} reports</small></span></summary>
    <div class="radio-observation-detail">
      <p class="radio-hint">BLE advertiser · device type unknown. This address may rotate.</p>
      <dl class="radio-fields"><div><dt>First / last seen</dt><dd>{time(props.observation.firstSeen)} / {time(props.observation.lastSeen)}</dd></div><div><dt>Advertising</dt><dd>{props.observation.legacy ? 'Legacy' : 'Extended'} · {props.observation.connectable ? 'Connectable' : 'Not connectable'}</dd></div><div><dt>PHY</dt><dd>{phy(props.observation.primaryPhy)} / {phy(props.observation.secondaryPhy)}</dd></div><div><dt>TX power</dt><dd>{props.observation.txPower === null ? 'Not reported' : `${props.observation.txPower} dBm`}</dd></div><div><dt>Company IDs</dt><dd>{props.observation.manufacturerIds.map(hexId).join(', ') || 'Not reported'}</dd></div><div><dt>Service UUIDs</dt><dd>{props.observation.serviceUuids.join('\n') || 'Not reported'}</dd></div></dl>
      <Show when={props.observation.advertisementHex}><p class="radio-hint">Advertisement bytes{props.observation.payloadTruncated ? ' · truncated' : ''}</p><pre class="radio-hex">{props.observation.advertisementHex}</pre></Show>
    </div>
  </details>;
}

function BluetoothPanel(props: { active: boolean; native: boolean; onActive: (active: boolean) => void }) {
  const [scan, setScan] = createSignal(emptyBle(props.native));
  const [duration, setDuration] = createSignal(60);
  const [query, setQuery] = createSignal('');
  const [limit, setLimit] = createSignal(100);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [notice, setNotice] = createSignal('');
  const byId = createMemo(() => new Map(scan().observations.map(item => [item.id, item])));
  const filtered = createMemo(() => {
    const term = query().trim().toLowerCase();
    return scan().observations.filter(item => `${item.name || ''} ${item.address} ${item.serviceUuids.join(' ')} ${item.manufacturerIds.map(hexId).join(' ')}`.toLowerCase().includes(term));
  });
  let disposed = false;
  let polling = false;
  let generation = 0;
  let initialized = false;
  function apply(value: BleSnapshot) { if (!disposed) { setScan(value); initialized = true; } }
  async function refresh() {
    if (!props.native || polling || busy() || disposed) return;
    const requestGeneration = generation; polling = true;
    try { const value = await bleStatus(); if (requestGeneration === generation) apply(value); }
    catch (reason) { if (!disposed && requestGeneration === generation) setError(String(reason)); }
    finally { polling = false; }
  }
  createEffect(() => { props.onActive(scan().active); });
  createEffect(() => { if (props.active) void refresh(); });
  createEffect(() => { query(); setLimit(100); });
  const timer = setInterval(() => { if (!document.hidden && (props.active || (initialized && scan().active))) void refresh(); }, 1000);
  onCleanup(() => { disposed = true; clearInterval(timer); });
  async function action(work: () => Promise<BleSnapshot>, message = '') {
    if (busy()) return;
    setError(''); setNotice('');
    if (!props.native) { setError('Bluetooth scanning requires the Android app. The browser does not observe nearby devices.'); return; }
    generation++; setBusy(true);
    try { apply(await work()); if (!disposed) setNotice(message); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); }
  }
  async function start(event: SubmitEvent) {
    event.preventDefault();
    if (!Number.isInteger(duration()) || duration() < 10 || duration() > 120) { setError('Choose a scan duration from 10 to 120 seconds.'); return; }
    await action(() => bleStart(duration()));
  }
  async function exportReport() {
    if (!props.native || busy() || !scan().observations.length) return;
    generation++; setBusy(true); setError(''); setNotice('');
    try { const location = await bleExport(); if (!disposed) setNotice(`JSON saved: ${location}`); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); }
  }
  return <section id="radio-bluetooth" class="radio-subview" hidden={!props.active} aria-label="Bluetooth observations">
    <div class="radio-scroll scroll-pane">
      <form id="ble-form" class="surface radio-setup" onSubmit={event => void start(event)}>
        <div class="panel-heading"><h2>Bluetooth LE scan</h2><span role="status">{scan().active ? 'Scanning' : scan().startedAt !== null ? 'Stopped' : 'Idle'}</span></div>
        <div class="radio-setup-body"><div class="scan-field"><label for="ble-duration">Scan duration (seconds)</label><input id="ble-duration" type="number" min="10" max="120" step="1" required value={duration()} disabled={scan().active || busy()} onInput={event => setDuration(event.currentTarget.valueAsNumber)} /></div>
          <p class="radio-hint">Observes Bluetooth LE advertising, including devices without SeekerShark. Allow Nearby devices and precise Location permission, and turn on Bluetooth and Location services. Keep the app visible and the screen on.</p>
          <p class="radio-hint">Entries are current address / advertising-set observations, not a count of phones. Android may filter or merge scan reports; RSSI is not a distance measurement.</p>
          <Show when={!props.native}><p class="radio-runtime">Android app required. No Bluetooth observations are generated in this browser.</p></Show>
          <Show when={props.native && !scan().supported}><p class="radio-runtime" role="status">Bluetooth LE scanning is unavailable on this device.</p></Show>
          <Show when={!scan().active && scan().observations.length}><p class="radio-hint">A new scan replaces this list. Export JSON to keep it.</p></Show>
        </div>
      </form>
      <Show when={error() || scan().lastError}><p class="detail-error radio-error" role="alert">{error() || scan().lastError}</p></Show>
      <Show when={notice()}><p class="scan-notice" role="status">{notice()}</p></Show>
      <section class="surface" aria-label="BLE scan summary"><div class="radio-counts"><span><b>{number(scan().advertisements)}</b> scan reports</span><span><b>{scan().observations.length}</b> retained entries</span><span>{(scan().elapsedMs / 1000).toFixed(1)} / {scan().durationSeconds} s</span></div><Show when={scan().droppedObservations}><p class="radio-hint radio-loss">{number(scan().droppedObservations)} entries evicted at the {scan().maxObservations}-entry limit.</p></Show></section>
      <section class="surface radio-results" aria-label="Observed BLE advertisers"><div class="radio-filter"><label for="ble-filter">Filter BLE observations</label><input id="ble-filter" placeholder="Name, address, service UUID or company ID" value={query()} onInput={event => setQuery(event.currentTarget.value)} autocomplete="off" spellcheck={false} /></div>
        <Show when={filtered().length} fallback={<p class="section-empty radio-empty">{query() ? 'No matching observations.' : scan().active ? 'Waiting for BLE scan reports…' : 'No Bluetooth observations. Start a scan on Android.'}</p>}>
          <For each={filtered().slice(0, limit()).map(item => item.id)}>{id => <Show when={byId().get(id)}>{item => <BleRow observation={item()} />}</Show>}</For>
          <Show when={filtered().length > limit()}><button class="secondary-button radio-more" onClick={() => setLimit(value => value + 100)}>Show 100 more</button></Show>
        </Show>
      </section>
    </div>
    <div class="radio-actions"><Show when={scan().active} fallback={<button class="capture-button" type="submit" form="ble-form" disabled={busy() || (props.native && !scan().supported)}>{busy() ? 'Starting…' : 'Start BLE scan'}</button>}><button class="capture-button recording" disabled={busy()} onClick={() => void action(bleStop)}>Stop BLE scan</button></Show><button class="secondary-button" disabled={busy() || scan().active || !scan().observations.length} onClick={() => void action(bleClear, 'Bluetooth observations cleared.')}>Clear observations</button><button class="secondary-button" disabled={busy() || !scan().observations.length} onClick={() => void exportReport()}>Export JSON</button></div>
  </section>;
}

function WifiSensorPanel(props: { active: boolean; native: boolean }) {
  const [sensor, setSensor] = createSignal(emptyWifiSensor());
  const [busy, setBusy] = createSignal(false);
  const [query, setQuery] = createSignal('');
  const [limit, setLimit] = createSignal(100);
  const [error, setError] = createSignal('');
  const [notice, setNotice] = createSignal('');
  const report = () => sensor().report;
  const filtered = createMemo(() => report()?.observations.filter(item => `${item.transmitter} ${item.channel} ${item.frameTypes.join(' ')}`.toLowerCase().includes(query().trim().toLowerCase())) ?? []);
  let input!: HTMLInputElement;
  let disposed = false;
  let generation = 0;
  let polling = false;
  async function refresh() {
    if (!props.native || busy() || polling || disposed) return;
    const requestGeneration = generation; polling = true;
    try { const value = await wifiSensorStatus(); if (!disposed && generation === requestGeneration) setSensor(value); }
    catch (reason) { if (!disposed && generation === requestGeneration) setError(String(reason)); }
    finally { polling = false; }
  }
  createEffect(() => { if (props.active) void refresh(); });
  createEffect(() => { query(); setLimit(100); });
  onCleanup(() => { disposed = true; });
  function selectFile() {
    setError(''); setNotice('');
    if (!props.native) { setError('Sensor report import requires the Android app. Live Wi-Fi sensor capture is not implemented.'); return; }
    input.click();
  }
  async function loadFile(file?: File) {
    if (!file || busy()) return;
    generation++; setBusy(true); setError(''); setNotice('');
    try {
      if (file.size > 1024 * 1024) throw new Error('Sensor report limit: 1 MiB.');
      const value = await wifiSensorImport(file);
      if (!disposed) { setSensor(value); setQuery(''); setLimit(100); setNotice(`Sensor report loaded: ${file.name}`); }
    } catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); input.value = ''; }
  }
  async function clear() {
    generation++; setBusy(true); setError(''); setNotice('');
    try { const value = await wifiSensorClear(); if (!disposed) setSensor(value); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); }
  }
  async function exportReport() {
    generation++; setBusy(true); setError(''); setNotice('');
    try { const location = await wifiSensorExport(); if (!disposed) setNotice(`JSON saved: ${location}`); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); }
  }
  return <section id="radio-wifi" class="radio-subview" hidden={!props.active} aria-label="Wi-Fi sensor observations">
    <input ref={input} type="file" accept=".json,application/json" aria-label="Sensor report file" hidden onChange={event => void loadFile(event.currentTarget.files?.[0])} />
    <div class="radio-scroll scroll-pane">
      <section class="surface"><div class="panel-heading"><h2>External Wi-Fi sensor</h2><span>Report import</span></div><div class="radio-setup-body"><p class="radio-hint">Sensor integration scaffold. Live capture and direct USB Wi-Fi drivers are not implemented. Import a version 1 JSON report from an external sensor to inspect its observations.</p><p class="radio-hint">1 MiB / 2,048 observations. Transmitter addresses are not a phone count. Existing PCAP import does not decode raw Radiotap / 802.11 captures.</p><button class="secondary-button radio-planned" disabled>Connect sensor</button></div></section>
      <Show when={error() || sensor().lastError}><p class="detail-error radio-error" role="alert">{error() || sensor().lastError}</p></Show>
      <Show when={notice()}><p class="scan-notice" role="status">{notice()}</p></Show>
      <Show when={report()}>{value => <section class="surface"><div class="panel-heading"><h2>{value().sensor.label}</h2><span>{value().observations.length} address observations</span></div><dl class="radio-fields radio-sensor-info"><div><dt>Adapter / driver</dt><dd>{value().sensor.adapter} / {value().sensor.driver}</dd></div><div><dt>Reported bands</dt><dd>{value().sensor.bands.join(', ')}</dd></div><div><dt>Reported channels</dt><dd>{value().sensor.channels.join(', ')}</dd></div><div><dt>Observation window</dt><dd>{new Date(value().startedAt).toISOString()} – {new Date(value().endedAt).toISOString()}</dd></div></dl></section>}</Show>
      <section class="surface radio-results" aria-label="Wi-Fi transmitter observations"><div class="radio-filter"><label for="wifi-filter">Filter Wi-Fi observations</label><input id="wifi-filter" placeholder="Transmitter address, channel or frame type" value={query()} onInput={event => setQuery(event.currentTarget.value)} autocomplete="off" spellcheck={false} /></div>
        <Show when={filtered().length} fallback={<p class="section-empty radio-empty">{query() ? 'No matching observations.' : report() ? 'The sensor report contains no transmitter observations.' : 'No sensor report loaded. Live capture is unavailable in this preview.'}</p>}>
          <For each={filtered().slice(0, limit())}>{item => <article class="radio-wifi-row"><div><code>{item.transmitter}</code><strong>{item.rssiDbm === null ? 'RSSI unknown' : `${item.rssiDbm} dBm`}</strong></div><p>{number(item.frames)} frames · channel {item.channel} · {item.frequencyMhz} MHz</p><p>{item.frameTypes.join(', ')} · {time(item.firstSeen)} – {time(item.lastSeen)}</p></article>}</For>
          <Show when={filtered().length > limit()}><button class="secondary-button radio-more" onClick={() => setLimit(value => value + 100)}>Show 100 more</button></Show>
        </Show>
      </section>
    </div>
    <div class="radio-actions"><button class="capture-button" disabled={busy()} onClick={selectFile}>Import sensor report</button><button class="secondary-button" disabled={busy() || !report()} onClick={() => void clear()}>Clear report</button><button class="secondary-button" disabled={busy() || !report()} onClick={() => void exportReport()}>Export JSON</button></div>
  </section>;
}

export default function RadioPanel(props: { active: boolean; native: boolean; onActive: (active: boolean) => void }) {
  const [mode, setMode] = createSignal<'bluetooth' | 'wifi'>('bluetooth');
  function switchWithKeyboard(event: KeyboardEvent) {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 'bluetooth' : event.key === 'End' ? 'wifi' : mode() === 'bluetooth' ? 'wifi' : 'bluetooth';
    setMode(next); document.getElementById(`radio-tab-${next}`)?.focus();
  }
  return <section class="radio-view" hidden={!props.active} aria-label="Radio observations">
    <div class="radio-tabs" role="tablist" aria-label="Radio source" onKeyDown={switchWithKeyboard}><button id="radio-tab-bluetooth" role="tab" aria-controls="radio-bluetooth" aria-selected={mode() === 'bluetooth'} tabindex={mode() === 'bluetooth' ? 0 : -1} onClick={() => setMode('bluetooth')}>Bluetooth</button><button id="radio-tab-wifi" role="tab" aria-controls="radio-wifi" aria-selected={mode() === 'wifi'} tabindex={mode() === 'wifi' ? 0 : -1} onClick={() => setMode('wifi')}>Wi-Fi sensor</button></div>
    <BluetoothPanel active={props.active && mode() === 'bluetooth'} native={props.native} onActive={props.onActive} />
    <WifiSensorPanel active={props.active && mode() === 'wifi'} native={props.native} />
  </section>;
}
