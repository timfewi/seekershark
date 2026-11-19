import { createEffect, createMemo, createSignal, For, onCleanup, Show } from 'solid-js';
import { emptyNearby, nearbyConfirm, nearbyConnect, nearbyDiscard, nearbyDisconnect, nearbyShare, nearbyStart, nearbyStatus, nearbyStop, type NearbySnapshot } from './api';

const peerStates = { found: 'Available', connecting: 'Connecting', confirming: 'Verify code', connected: 'Connected' };
const transferStates = { sending: 'Sending', receiving: 'Receiving', received: 'Ready to open', sent: 'Sent', failed: 'Failed' };
const bytes = (value: number) => value < 1024 ? `${value} B` : value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} KiB` : `${(value / 1024 / 1024).toFixed(1)} MiB`;
function savedName() {
  try { return localStorage.getItem('seekershark.nearbyName') || 'My Seeker'; } catch { return 'My Seeker'; }
}

export default function NearbyPanel(props: {
  active: boolean; native: boolean; canShare: boolean; captureRunning: boolean;
  onActive: (active: boolean) => void; onImport: (id: string) => Promise<void>;
}) {
  const [nearby, setNearby] = createSignal(emptyNearby(props.native));
  const [name, setName] = createSignal(savedName());
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [notice, setNotice] = createSignal('');
  const connected = createMemo(() => nearby().peers.filter(peer => peer.state === 'connected').length);
  let disposed = false;
  let polling = false;
  let generation = 0;
  let initialized = false;
  let dirty = false;
  function apply(value: NearbySnapshot) {
    if (disposed) return;
    // Keep unchanged rows mounted while polling, including focused pairing controls.
    const oldPeers = new Map(nearby().peers.map(peer => [peer.id, peer]));
    const oldTransfers = new Map(nearby().transfers.map(transfer => [transfer.id, transfer]));
    setNearby({ ...value,
      peers: value.peers.map(peer => JSON.stringify(oldPeers.get(peer.id)) === JSON.stringify(peer) ? oldPeers.get(peer.id)! : peer),
      transfers: value.transfers.map(transfer => JSON.stringify(oldTransfers.get(transfer.id)) === JSON.stringify(transfer) ? oldTransfers.get(transfer.id)! : transfer),
    });
    if (!initialized && !dirty && value.name) setName(value.name);
    initialized = true;
  }
  async function refresh() {
    if (!props.native || polling || busy() || disposed) return;
    const requestGeneration = generation;
    polling = true;
    try { const value = await nearbyStatus(); if (requestGeneration === generation) apply(value); }
    catch (reason) { if (!disposed && requestGeneration === generation) setError(String(reason)); }
    finally { polling = false; }
  }
  createEffect(() => props.onActive(nearby().active));
  createEffect(() => { if (props.active) void refresh(); });
  const timer = setInterval(() => { if (!document.hidden && (props.active || nearby().active)) void refresh(); }, 750);
  onCleanup(() => { disposed = true; clearInterval(timer); });

  async function action(work: () => Promise<NearbySnapshot>, message = '') {
    if (busy()) return;
    setError(''); setNotice('');
    if (!props.native) { setError('Nearby requires the Android app and Google Play services. The browser does not search for devices.'); return; }
    generation++; setBusy(true);
    try { apply(await work()); if (!disposed) setNotice(message); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); }
  }
  async function start(event: SubmitEvent) {
    event.preventDefault();
    const value = name().trim();
    if (!value) { setError('Enter a device name.'); return; }
    try { localStorage.setItem('seekershark.nearbyName', value); } catch { /* Storage can be disabled. */ }
    await action(() => nearbyStart(value));
  }
  async function openCapture(id: string) {
    if (busy() || props.captureRunning) return;
    generation++; setBusy(true); setError(''); setNotice('');
    try { await props.onImport(id); }
    catch (reason) { if (!disposed) setError(String(reason)); }
    finally { setBusy(false); void refresh(); }
  }

  return <section class="nearby-view" hidden={!props.active} aria-label="Nearby devices">
    <div class="nearby-scroll scroll-pane">
      <form id="nearby-form" class="surface nearby-setup" onSubmit={event => void start(event)}>
        <div class="panel-heading"><h2>Nearby</h2><span role="status">{nearby().active ? connected() ? `${connected()} connected` : 'Discovering' : 'Off'}</span></div>
        <div class="nearby-setup-body">
          <div class="scan-field"><label for="nearby-name">Your device name</label><input id="nearby-name" value={name()} maxlength="32" required disabled={nearby().active || busy()} autocomplete="off" onInput={event => { dirty = true; setName(event.currentTarget.value); }} /></div>
          <p>Open Nearby on both phones. Discover other SeekerShark users without a shared Wi-Fi network or internet, then compare the connection code.</p>
          <p class="nearby-runtime">{props.native ? 'Bluetooth, Wi-Fi, Location services and Google Play services are required. Keep both apps open.' : 'Android app required. Device discovery is unavailable in this browser.'}</p>
          <Show when={props.native && !nearby().supported}><p class="nearby-runtime" role="status">Nearby is unavailable. Install or update Google Play services, then reopen this view.</p></Show>
        </div>
      </form>
      <Show when={error() || nearby().lastError}><p class="detail-error nearby-error" role="alert">{error() || nearby().lastError}</p></Show>
      <Show when={notice()}><p class="scan-notice" role="status">{notice()}</p></Show>
      <section class="surface nearby-peers" aria-label="Discovered devices">
        <div class="panel-heading"><h2>Devices</h2><span>{nearby().peers.length} visible</span></div>
        <Show when={nearby().peers.length} fallback={<p class="section-empty nearby-empty">{nearby().active ? 'No SeekerShark devices found yet. Enable Nearby on the other phone.' : 'Start Nearby to make this phone discoverable and find other participants.'}</p>}>
          <For each={nearby().peers}>{peer => <article class="nearby-peer" aria-label={`Device ${peer.name}`}>
            <div class="nearby-row-heading"><strong>{peer.name}</strong><span>{peerStates[peer.state]}</span></div>
            <Show when={peer.state === 'confirming'}><div class="nearby-pairing">
              <p>Confirm only if both phones show this code:</p><code class="nearby-code" aria-label="Connection code">{peer.authenticationCode || 'Unavailable'}</code>
              <div class="nearby-buttons"><button class="secondary-button" disabled={busy() || !peer.authenticationCode} onClick={() => void action(() => nearbyConfirm(peer.id, true))}>Confirm code</button><button class="secondary-button" disabled={busy()} onClick={() => void action(() => nearbyConfirm(peer.id, false))}>Reject</button></div>
            </div></Show>
            <Show when={peer.state === 'found'}><button class="secondary-button" aria-label={`Connect to ${peer.name}`} disabled={busy()} onClick={() => void action(() => nearbyConnect(peer.id))}>Connect</button></Show>
            <Show when={peer.state === 'connecting'}><button class="secondary-button" disabled={busy()} onClick={() => void action(() => nearbyDisconnect(peer.id))}>Cancel connection</button></Show>
            <Show when={peer.state === 'connected'}><div class="nearby-buttons"><button class="secondary-button" disabled={busy() || !props.canShare} onClick={() => void action(() => nearbyShare(peer.id), 'Capture transfer started. Check the transfer status below.')}>Share current capture</button><button class="secondary-button" disabled={busy()} aria-label={`Disconnect from ${peer.name}`} onClick={() => void action(() => nearbyDisconnect(peer.id))}>Disconnect</button></div>
              <p class="nearby-hint">{props.canShare ? 'Shares a snapshot of your current capture, only when you tap Share.' : 'Record or open a PCAP to share. Browser demo packets are not shared.'}</p>
            </Show>
          </article>}</For>
        </Show>
      </section>
      <section class="surface nearby-transfers" aria-label="Capture transfers">
        <div class="panel-heading"><h2>Capture transfers</h2><span>PCAP · up to 40 MiB</span></div>
        <Show when={nearby().transfers.length} fallback={<p class="section-empty nearby-empty">Received captures appear here. Nothing is opened automatically.</p>}>
          <For each={nearby().transfers}>{transfer => <article class="nearby-transfer" aria-label={`Transfer ${transfer.name}`}>
            <div class="nearby-row-heading"><strong>{transfer.name}</strong><span>{transferStates[transfer.state]}</span></div>
            <p class="nearby-hint">{transfer.peerName} · {bytes(transfer.bytes)} / {bytes(transfer.totalBytes)}</p>
            <Show when={transfer.state === 'sending' || transfer.state === 'receiving'}><progress aria-label={`Transfer progress for ${transfer.name}`} value={transfer.bytes} max={transfer.totalBytes || 1} /></Show>
            <Show when={transfer.error}><p class="detail-error" role="alert">{transfer.error}</p></Show>
            <Show when={transfer.state === 'received'}><div class="nearby-buttons"><button class="secondary-button" disabled={busy() || props.captureRunning} onClick={() => void openCapture(transfer.id)}>Open capture</button><button class="secondary-button" disabled={busy()} onClick={() => void action(() => nearbyDiscard(transfer.id))}>Discard</button></div><p class="nearby-hint">{props.captureRunning ? 'Stop local capture before opening a received capture.' : 'Opening replaces the displayed capture. Export it first if you want to keep it.'}</p></Show>
          </article>}</For>
        </Show>
      </section>
      <details class="surface scan-capabilities nearby-limits"><summary>Same Wi-Fi & limits</summary><div>
        <p>The same Wi-Fi network can make direct connections easier. Use Scan with a known IP or subnet to check reachable TCP services. Guest networks and access-point isolation can block connections.</p>
        <p>Being on the same Wi-Fi does not expose another phone's packets. Each participating phone captures its own traffic and explicitly shares a PCAP. HTTPS stays encrypted.</p>
        <p>Nearby discovers participating SeekerShark apps, not every nearby phone. It does not provide remote live capture. Leaving the app stops Nearby and clears temporary transfers.</p>
      </div></details>
    </div>
    <div class="nearby-actions"><Show when={nearby().active} fallback={<button class="capture-button" type="submit" form="nearby-form" disabled={busy() || (props.native && !nearby().supported)}>{busy() ? 'Starting…' : 'Start Nearby'}</button>}><button class="capture-button recording" disabled={busy()} onClick={() => void action(nearbyStop, 'Nearby stopped. Temporary transfers cleared.')}>Stop Nearby</button></Show></div>
  </section>;
}
