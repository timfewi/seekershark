import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { emptyScan, scanExport, scanStart, scanStatus, scanStop, type ScanSnapshot } from './api';

export const COMMON_PORTS = '21,22,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,1883,2049,2375,3000,3306,3389,5432,5672,5900,6379,8000,8080,8443,8888,9090,9200,11211,27017';
const phases = { idle: 'Idle', resolving: 'Resolving', running: 'Scanning', cancelling: 'Stopping', completed: 'Completed', cancelled: 'Cancelled', failed: 'Failed' };
const number = (value: number) => new Intl.NumberFormat('en-US').format(value);
const endpoint = (host: string, port: number) => `${host.includes(':') ? `[${host}]` : host}:${port}`;

export default function ScanPanel(props: { active: boolean; native: boolean; target: string; onTarget: (value: string) => void; onRunning: (value: boolean) => void; onInspect: (host: string) => void }) {
  const [scan, setScan] = createSignal(emptyScan());
  const [ports, setPorts] = createSignal(COMMON_PORTS);
  const [services, setServices] = createSignal(false);
  const [concurrency, setConcurrency] = createSignal(128);
  const [timeout, setTimeout] = createSignal(1000);
  const [probeTimeout, setProbeTimeout] = createSignal(1000);
  const [limit, setLimit] = createSignal(150);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [notice, setNotice] = createSignal('');
  const active = createMemo(() => ['resolving', 'running', 'cancelling'].includes(scan().phase));
  let polling = false;
  let initialized = false;
  let disposed = false;
  let dirty = false;
  let generation = 0;
  let scroll!: HTMLDivElement;

  function apply(value: ScanSnapshot) {
    if (disposed) return;
    // Results are immutable after a check finishes. Preserve row identity so
    // polling does not close expanded banners or replace focused controls.
    const previous = new Map((scan().id === value.id ? scan().results : []).map(result => [`${result.address}/${result.port}`, result]));
    setScan({ ...value, results: value.results.map(result => previous.get(`${result.address}/${result.port}`) ?? result) });
    if (!initialized && !dirty && value.request && !props.target) {
      props.onTarget(value.request.target); setPorts(value.request.ports);
      setServices(value.request.serviceDetection); setConcurrency(value.request.concurrency);
      setTimeout(value.request.timeoutMs); setProbeTimeout(value.request.probeTimeoutMs);
    }
    initialized = true;
  }
  async function refresh() {
    if (!props.native || polling || busy()) return;
    const requestGeneration = generation;
    polling = true;
    try { const value = await scanStatus(limit()); if (generation === requestGeneration) apply(value); }
    catch (reason) { if (!disposed && generation === requestGeneration) setError(String(reason)); }
    finally { polling = false; }
  }
  createEffect(() => props.onRunning(active()));
  createEffect(() => { if (props.active) void refresh(); });
  const timer = setInterval(() => { if (!document.hidden && (props.active || active())) void refresh(); }, 750);
  onMount(() => { void refresh(); });
  onCleanup(() => { disposed = true; clearInterval(timer); });

  async function start(event: SubmitEvent) {
    event.preventDefault(); setError(''); setNotice(''); dirty = true;
    scroll.scrollTo({ top: 0 });
    if (!props.native) { setError('Port scanning requires the Android app. The browser cannot open TCP sockets.'); return; }
    generation++; setBusy(true); setLimit(150);
    try { apply(await scanStart({ target: props.target, ports: ports(), concurrency: concurrency(), timeoutMs: timeout(), serviceDetection: services(), probeTimeoutMs: probeTimeout() })); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  async function stop() {
    generation++; setBusy(true); setError('');
    try { apply(await scanStop()); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  async function exportReport() {
    setBusy(true); setError(''); setNotice('');
    try { setNotice(`JSON saved: ${await scanExport()}`); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }

  return <section class="scan-view" hidden={!props.active} aria-label="Network scanner">
    <div ref={scroll} class="scan-scroll scroll-pane">
      <form id="scan-form" class="surface scan-form" onSubmit={event => void start(event)} onInput={() => { dirty = true; }}>
        <fieldset disabled={active() || busy()}>
          <div class="scan-field"><label for="scan-target">Target</label><input id="scan-target" placeholder="192.168.1.1 · example.com · 192.168.1.0/24" value={props.target} onInput={event => props.onTarget(event.currentTarget.value)} required maxlength="253" autocapitalize="off" autocomplete="off" spellcheck={false} /></div>
          <div class="scan-field"><label for="scan-ports">TCP ports</label><input id="scan-ports" value={ports()} onInput={event => setPorts(event.currentTarget.value)} required maxlength="8192" placeholder="22,80,443 or 1-65535" autocapitalize="off" spellcheck={false} /></div>
          <div class="scan-presets" aria-label="Port presets"><For each={[
            ['Common', COMMON_PORTS], ['1–1024', '1-1024'], ['All ports', '1-65535'],
          ]}>{([label, value]) => <button type="button" aria-pressed={ports() === value} onClick={() => { dirty = true; setPorts(value); }}>{label}</button>}</For></div>
          <div class="scan-mode" role="group" aria-label="Scan mode"><button type="button" aria-pressed={!services()} onClick={() => { dirty = true; setServices(false); }}>Fast TCP</button><button type="button" aria-pressed={services()} onClick={() => { dirty = true; setServices(true); }}>Service probes</button></div>
          <details class="scan-timing"><summary>Timing <span>{concurrency()} sockets · {timeout()} ms</span></summary><div>
            <div class="scan-field"><label for="scan-concurrency">Concurrency</label><input id="scan-concurrency" type="number" min="1" max="256" required value={concurrency()} onInput={event => setConcurrency(event.currentTarget.valueAsNumber)} /></div>
            <div class="scan-field"><label for="scan-timeout">Connect timeout (ms)</label><input id="scan-timeout" type="number" min="100" max="10000" required value={timeout()} onInput={event => setTimeout(event.currentTarget.valueAsNumber)} /></div>
            <Show when={services()}><div class="scan-field"><label for="scan-probe-timeout">Probe timeout (ms)</label><input id="scan-probe-timeout" type="number" min="100" max="5000" required value={probeTimeout()} onInput={event => setProbeTimeout(event.currentTarget.valueAsNumber)} /></div></Show>
          </div></details>
        </fieldset>
      </form>
      <Show when={error() || scan().error}><p class="detail-error" role="alert">{error() || scan().error}</p></Show>
      <Show when={notice()}><p class="scan-notice" role="status">{notice()}</p></Show>
      <section class="surface scan-status" aria-label="Scan progress"><div class="panel-heading"><h2>{phases[scan().phase]}</h2><span>{(scan().elapsedMs / 1000).toFixed(1)} s</span></div>
        <Show when={scan().request}><code class="scan-report-target">{scan().request!.target}</code></Show>
        <progress aria-label="Completed connection checks" value={scan().completed} max={scan().total || 1} />
        <div class="scan-counts"><span><b>{number(scan().completed)}</b>/{number(scan().total)} checked</span><span><b>{number(scan().open)}</b> open</span><span>{number(scan().closed)} closed</span><span>{number(scan().timedOut)} timed out</span><span>{number(scan().errors)} errors</span></div>
        <Show when={scan().addresses.length}><details class="scan-targets"><summary>{number(scan().addresses.length)} targets · {number(scan().portCount)} ports</summary><code>{scan().addresses.join('\n')}</code></details></Show>
      </section>
      <section class="surface scan-results" aria-label="Open ports"><div class="panel-heading"><h2>Open ports</h2><span>{number(scan().resultsRetained)} retained</span></div>
        <Show when={scan().results.length} fallback={<p class="section-empty">{active() ? 'Waiting for open ports…' : scan().completed ? 'No open ports found.' : 'No scan results.'}</p>}>
          <For each={scan().results}>{result => <details class="scan-result"><summary>
            <code>{endpoint(result.address, result.port)}</code><span>{result.service}<small>{result.evidence === 'response' ? 'response' : result.evidence === 'port' ? 'port hint' : 'unidentified'}</small></span><span>{result.connectMs.toFixed(1)} ms</span>
          </summary><div class="scan-result-detail">
            <Show when={result.product}><strong>{result.product}</strong></Show>
            <Show when={result.portHint}><p>Port hint: {result.portHint}</p></Show>
            <Show when={result.banner}><pre>{result.banner}</pre></Show>
            <Show when={result.evidence !== 'response'}><p>Service not verified by a response.</p></Show>
            <button class="secondary-button" onClick={() => props.onInspect(result.address)}>Filter captured packets</button>
          </div></details>}</For>
          <Show when={scan().resultsRetained > scan().results.length}><button class="secondary-button scan-more" onClick={() => { setLimit(value => value + 150); void refresh(); }}>Show 150 more</button></Show>
        </Show>
        <Show when={scan().resultsDropped}><p class="detail-error">{number(scan().resultsDropped)} open results exceeded the 4,096-result storage limit. Counts include them; export contains retained results.</p></Show>
      </section>
      <details class="surface scan-capabilities"><summary>Engine & limits</summary><div>
        <p>Native Rust TCP connect scanner. Fast discovery is similar to RustScan; selected service checks provide a subset of Nmap-style detection. RustScan and Nmap binaries are not bundled.</p>
        <p>HTTP HEAD on common web ports, server-first banners, TLS 1.2 ClientHello on common TLS ports. Port hints are not detected services. Timeouts do not prove a port is filtered.</p>
        <p>Up to 256 target addresses, 1,048,576 checks, 4,096 retained results, and 15 minutes per job. IPv4 CIDRs omit network/broadcast except /31 and /32.</p>
        <p>No raw SYN/UDP scan, OS fingerprinting, NSE scripts, or TLS version enumeration. Scan sockets bypass SeekerShark's VPN capture. Keep the app in the foreground.</p>
      </div></details>
    </div>
    <div class="scan-actions"><Show when={active()} fallback={<button class="capture-button" type="submit" form="scan-form" disabled={busy()}>Scan</button>}><button class="capture-button recording" disabled={busy() || scan().phase === 'cancelling'} onClick={() => void stop()}>{scan().phase === 'cancelling' ? 'Stopping…' : 'Stop scan'}</button></Show><button class="secondary-button" disabled={busy() || !scan().completed} onClick={() => void exportReport()}>Export JSON</button></div>
  </section>;
}
