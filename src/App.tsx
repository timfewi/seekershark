import { createEffect, createMemo, createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { captureStatus, clearCapture, emptyCapture, exportPcap, importPcap, isNative, nearbyImport, packetDetail, saveFile, savePcap, savePcapData, snapshot, startCapture, stopCapture, type Capture, type Packet } from './api';
import { onBackButtonPress } from '@tauri-apps/api/app';
import type { PluginListener } from '@tauri-apps/api/core';
import ScanPanel from './ScanPanel';
import NearbyPanel from './NearbyPanel';
import RadioPanel from './RadioPanel';
import { demoCapture, demoPcap } from './demo';
import { beautifyPacket, packetSummary } from './beautify';

type IconName = 'fin' | 'play' | 'stop' | 'upload' | 'download' | 'search' | 'close' | 'packets' | 'chart' | 'settings' | 'arrow' | 'check' | 'shield' | 'trash' | 'file' | 'info' | 'back' | 'scan' | 'nearby' | 'radio';
const paths: Record<IconName, string> = {
  fin: 'M3 19h18M6 17c5-1 6-9 6-13 5 3 6 8 6 13H6Z', play: 'm8 5 11 7-11 7V5Z', stop: 'M6 6h12v12H6z',
  upload: 'M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5', download: 'M12 3v13m-5-5 5 5 5-5M4 17v4h16v-4',
  search: 'm21 21-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z', close: 'm6 6 12 12M6 18 18 6',
  packets: 'M4 4h16v5H4zM4 15h16v5H4zM8 6.5h.01M8 17.5h.01', chart: 'M4 20V4m0 16h17M9 16v-5m5 5V7m5 9V3',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM3 10l3-1 1-3 3-1 2-3 2 3 3 1 1 3 3 1v4l-3 1-1 3-3 1-2 3-2-3-3-1-1-3-3-1z',
  scan: 'M12 3a9 9 0 1 0 9 9M12 3v9l6-6M12 7a5 5 0 1 0 5 5M12 12l8-8',
  nearby: 'M8 8a6 6 0 0 1 8 0M5 5a10 10 0 0 1 14 0M12 12h.01M7 21h10l-5-9-5 9Z',
  radio: 'M5 5a10 10 0 0 0 0 14M8 8a6 6 0 0 0 0 8M19 5a10 10 0 0 1 0 14M16 8a6 6 0 0 1 0 8M12 11v2',
  back: 'M20 12H4m6-6-6 6 6 6',
  arrow: 'M4 12h16m-6-6 6 6-6 6', check: 'm5 12 4 4L19 6', shield: 'm12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6l8-4Z',
  trash: 'M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7', file: 'M14 2H5v20h14V7l-5-5Zm0 0v6h5M8 12h8m-8 4h6',
  info: 'M12 11v6m0-10h.01M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z',
};
function Icon(props: { name: IconName; size?: number }) {
  return <svg width={props.size ?? 20} height={props.size ?? 20} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[props.name]} /></svg>;
}
function BeautifySwitch(props: { enabled: boolean; onChange: (enabled: boolean) => void }) {
  return <label class="beautify-switch"><span>Beautify</span><input type="checkbox" role="switch" aria-label="Beautify" checked={props.enabled} onChange={event => props.onChange(event.currentTarget.checked)} /><span class="switch-track" aria-hidden="true" /></label>;
}
function initialBeautify() {
  try { return localStorage.getItem('seekershark.beautify') === 'true'; } catch { return false; }
}
const bytes = (value: number) => value < 1000 ? `${value} B` : value < 1e6 ? `${(value / 1000).toFixed(1)} kB` : `${(value / 1e6).toFixed(2)} MB`;
const number = (value: number) => new Intl.NumberFormat('en-US').format(value);
const endpoint = (host: string, port: number | null) => port == null ? host : `${host.includes(':') ? `[${host}]` : host}:${port}`;
const tone = (protocol: string) => ['DNS', 'UDP'].includes(protocol) ? 'gray' : ['TLS', 'QUIC'].includes(protocol) ? 'red' : ['HTTP', 'TCP'].includes(protocol) ? 'light' : 'muted';
type Tab = 'packets' | 'analysis' | 'scan' | 'nearby' | 'radio' | 'tools';

export default function App() {
  const native = isNative();
  const [capture, setCapture] = createSignal(native ? emptyCapture() : demoCapture());
  const [mode, setMode] = createSignal<'empty' | 'demo' | 'file' | 'live'>(native ? 'empty' : 'demo');
  const [running, setRunning] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [notice, setNotice] = createSignal('');
  const [tab, setTab] = createSignal<Tab>('packets');
  const [scanTarget, setScanTarget] = createSignal('');
  const [scanRunning, setScanRunning] = createSignal(false);
  const [nearbyActive, setNearbyActive] = createSignal(false);
  const [bleActive, setBleActive] = createSignal(false);
  const [query, setQuery] = createSignal('');
  const [limit, setLimit] = createSignal(150);
  const [selected, setSelected] = createSignal<Packet | null>(null);
  const [detailError, setDetailError] = createSignal('');
  const [detailTab, setDetailTab] = createSignal<'layers' | 'hex'>('layers');
  const [hexLimit, setHexLimit] = createSignal(256);
  const [fileName, setFileName] = createSignal('');
  const [beautify, setBeautify] = createSignal(initialBeautify());
  const readable = createMemo(() => beautify() && selected() ? beautifyPacket(selected()!) : null);
  createEffect(() => { try { localStorage.setItem('seekershark.beautify', String(beautify())); } catch { /* Storage can be disabled. */ } });
  let input!: HTMLInputElement;
  let workspace!: HTMLElement;
  let filterHelp!: HTMLDetailsElement;
  const [filterHelpOpen, setFilterHelpOpen] = createSignal(false);
  const [backDepth, setBackDepth] = createSignal(0);
  const backStack: Array<{ tab: Tab; query: string; scroll: number }> = [];
  const canGoBack = createMemo(() => selected() !== null || tab() !== 'packets' || backDepth() > 0 || filterHelpOpen());
  function closeHelp() { if (filterHelp) filterHelp.open = false; setFilterHelpOpen(false); }
  function pushView() {
    backStack.push({ tab: tab(), query: query(), scroll: workspace?.querySelector<HTMLElement>('.packet-table, .scroll-pane')?.scrollTop ?? 0 });
    if (backStack.length > 32) backStack.shift();
    setBackDepth(backStack.length);
    closeHelp();
  }
  function resetNavigation() {
    backStack.length = 0; setBackDepth(0); detailRequest++; setSelected(null); closeHelp();
  }
  function goBack() {
    if (!selected() && filterHelpOpen()) { closeHelp(); return; }
    detailRequest++; setSelected(null); setDetailError('');
    const previous = backStack.pop(); setBackDepth(backStack.length);
    setTab(previous?.tab ?? 'packets');
    if (previous) setQuery(previous.query);
    requestAnimationFrame(() => workspace?.querySelector<HTMLElement>('.packet-table, .scroll-pane')?.scrollTo({ top: previous?.scroll ?? 0 }));
  }
  function navigateTab(next: Tab) {
    if (next === tab() && !selected()) return;
    if (next === 'packets') { resetNavigation(); setTab(next); return; }
    pushView(); setTab(next);
  }
  function drillDown(filter: string) { pushView(); setQuery(filter); setTab('packets'); }

  // The native handler is installed only while there is an in-app destination
  // to return to. At the root, Android keeps its normal back/home behavior.
  createEffect(() => {
    if (!native || !/Android/i.test(navigator.userAgent) || !canGoBack()) return;
    let disposed = false;
    let listener: PluginListener | undefined;
    void onBackButtonPress(() => goBack()).then(value => {
      if (disposed) void value.unregister().catch(() => {});
      else listener = value;
    }).catch(error => { if (!disposed) setError(`Android Back: ${String(error)}`); });
    onCleanup(() => { disposed = true; if (listener) void listener.unregister().catch(() => {}); });
  });
  let dialog!: HTMLDialogElement;
  let polling = false;
  let detailRequest = 0;
  let captureGeneration = 0;
  function applyCapture(next: Capture) {
    const previous = new Map(capture().packets.map(packet => [packet.id, packet]));
    setCapture({ ...next, packets: next.packets.map(packet => previous.get(packet.id) ?? packet) });
  }

  const protocols = createMemo(() => {
    const counts = new Map<string, { name: string; count: number; bytes: number }>();
    for (const packet of capture().packets) {
      const value = counts.get(packet.protocol) ?? { name: packet.protocol, count: 0, bytes: 0 };
      value.count++; value.bytes += packet.length; counts.set(packet.protocol, value);
    }
    return [...counts.values()].sort((a, b) => b.count - a.count);
  });
  const endpoints = createMemo(() => {
    const map = new Map<string, number>();
    for (const p of capture().packets) { map.set(p.source, (map.get(p.source) ?? 0) + 1); map.set(p.destination, (map.get(p.destination) ?? 0) + 1); }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  });
  const filtered = createMemo(() => {
    const terms = query().toLowerCase().trim().split(/\s+/).filter(Boolean);
    return capture().packets.filter(packet => terms.every(term => {
      if (term.startsWith('proto:')) return packet.protocol.toLowerCase() === term.slice(6);
      if (term.startsWith('port:')) return [packet.sourcePort, packet.destinationPort].some(port => String(port) === term.slice(5));
      if (term.startsWith('host:')) return `${packet.source} ${packet.destination}`.toLowerCase().includes(term.slice(5));
      return `${packet.source} ${packet.destination} ${packet.protocol} ${packet.info} ${packet.sourcePort} ${packet.destinationPort} ${beautify() ? packetSummary(packet) : ''}`.toLowerCase().includes(term);
    }));
  });
  const startTime = createMemo(() => capture().packets[0]?.timestamp ?? 0);
  const duration = createMemo(() => {
    const packets = capture().packets;
    return packets.length > 1 ? Math.max(0, packets[packets.length - 1].timestamp - packets[0].timestamp).toFixed(2) : '0.00';
  });
  const chart = createMemo(() => {
    const packets = capture().packets;
    const bins = Array.from({ length: 44 }, () => 0);
    const begin = packets[0]?.timestamp ?? 0;
    const span = Math.max(.01, (packets.at(-1)?.timestamp ?? begin) - begin);
    for (const p of packets) bins[Math.min(43, Math.floor((p.timestamp - begin) / span * 43))] += p.length;
    const max = Math.max(1, ...bins);
    return bins.map((value, index) => `${index * 12},${70 - value / max * 58}`).join(' ');
  });
  const hexLines = createMemo(() => {
    const hex = (selected()?.hex ?? '').replace(/[^a-f0-9]/gi, '');
    const data = hex.slice(0, hexLimit() * 2).match(/.{2}/g) ?? [];
    return Array.from({ length: Math.ceil(data.length / 16) }, (_, row) => {
      const slice = data.slice(row * 16, row * 16 + 16);
      return { offset: (row * 16).toString(16).padStart(4, '0'), hex: slice.join(' '), ascii: slice.map(byte => { const code = parseInt(byte, 16); return code > 31 && code < 127 ? String.fromCharCode(code) : '·'; }).join('') };
    });
  });
  createEffect(() => { query(); setLimit(150); });
  createEffect(() => {
    if (selected() && !dialog.open) dialog.showModal();
    else if (!selected() && dialog.open) dialog.close();
  });

  const refresh = async () => {
    if (!native || polling || !running()) return;
    polling = true;
    const generation = captureGeneration;
    try {
      const [current, status] = await Promise.all([snapshot(), captureStatus()]);
      if (generation === captureGeneration) {
        applyCapture(current); setRunning(status.running);
        if (status.lastError) setError(status.lastError);
      }
    } catch (e) { setError(String(e)); setRunning(false); }
    finally { polling = false; }
  };
  const timer = setInterval(() => { if (!document.hidden) void refresh(); }, 1000);
  onCleanup(() => clearInterval(timer));
  onMount(() => {
    if (!native) return;
    const generation = captureGeneration;
    void Promise.all([snapshot(), captureStatus()]).then(([current, status]) => {
      if (generation !== captureGeneration) return;
      applyCapture(current); setRunning(status.running);
      if (status.running) setMode('live');
      else if (current.packets.length) { setMode('file'); setFileName('Capture buffer'); }
      if (status.lastError) setError(status.lastError);
    }).catch(e => { if (generation === captureGeneration) setError(String(e)); });
  });
  async function toggleCapture() {
    setError(''); setNotice('');
    if (!native) { setError('Live capture requires the Android app.'); return; }
    setBusy(true);
    captureGeneration++;
    try {
      if (running()) { await stopCapture(); setRunning(false); setCapture(await snapshot()); setNotice('Capture stopped.'); }
      else { const status = await startCapture(); resetNavigation(); setMode('live'); setRunning(status.running); setCapture(await snapshot()); setTab('packets'); if (status.lastError) setError(status.lastError); }
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }
  async function loadFile(file?: File) {
    if (!file) return;
    setError(''); setNotice(''); setBusy(true);
    captureGeneration++;
    try {
      if (file.size > 64 * 1024 * 1024) throw new Error('PCAP limit: 64 MiB.');
      if (running()) { await stopCapture(); setRunning(false); }
      const result = await importPcap(file);
      resetNavigation(); setCapture(result); setFileName(file.name); setMode('file'); setQuery(''); setTab('packets');
      setNotice(`${number(result.totalPackets)} packets loaded from ${file.name}.`);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); input.value = ''; }
  }
  async function exportFile() {
    if (!capture().packets.length) return;
    setBusy(true); setError('');
    try {
      if (native) {
        const path = mode() === 'demo' ? await savePcapData(demoPcap(capture())) : await savePcap();
        setNotice(`PCAP saved: ${path}`);
      } else {
        const data = mode() === 'demo' ? demoPcap(capture()) : Uint8Array.from(await exportPcap());
        saveFile(data, `seekershark-${mode() === 'demo' ? 'demo' : 'capture'}-${new Date().toISOString().slice(0, 10)}.pcap`);
        setNotice('PCAP export created.');
      }
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }
  async function openNearbyCapture(id: string) {
    if (running() || busy()) throw new Error('Stop local capture before opening a received capture.');
    setBusy(true); setError(''); setNotice(''); captureGeneration++;
    try {
      const result = await nearbyImport(id);
      pushView(); detailRequest++; setSelected(null);
      setCapture(result.capture); setFileName(`Nearby · ${result.peerName} · ${result.name}`);
      setMode('file'); setQuery(''); setTab('packets');
      setNotice(`${number(result.capture.totalPackets)} packets opened from ${result.peerName}.`);
    } finally { setBusy(false); }
  }
  async function openPacket(packet: Packet) {
    pushView();
    const request = ++detailRequest;
    setSelected(packet); setDetailError(''); setDetailTab('layers'); setHexLimit(256);
    if (native && mode() !== 'demo' && !packet.layers.length) {
      try { const detail = await packetDetail(packet.id); if (request === detailRequest && selected()?.id === packet.id) setSelected(detail); }
      catch (e) { if (request === detailRequest) setDetailError(String(e)); }
    }
  }
  async function clear() {
    setError(''); setBusy(true);
    captureGeneration++;
    try {
      if (running()) { await stopCapture(); setRunning(false); }
      if (native && mode() !== 'demo') await clearCapture();
      resetNavigation(); setCapture(emptyCapture()); setMode('empty'); setSelected(null); setNotice('Buffer cleared.');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }
  function loadDemo() { resetNavigation(); captureGeneration++; setCapture(demoCapture()); setMode('demo'); setQuery(''); setTab('packets'); setError(''); setNotice('Demo loaded.'); }

  const navItems = [
    { id: 'packets', icon: 'packets', label: 'Packets' },
    { id: 'analysis', icon: 'chart', label: 'Analysis' },
    { id: 'scan', icon: 'scan', label: 'Scan' },
    { id: 'nearby', icon: 'nearby', label: 'Nearby' },
    { id: 'radio', icon: 'radio', label: 'Radio' },
    { id: 'tools', icon: 'settings', label: 'Session' },
  ] as const;
  const modeLabel = () => mode() === 'demo' ? 'DEMO' : running() ? 'LIVE' : mode() === 'file' ? 'PCAP' : mode() === 'live' ? 'STOP' : 'IDLE';
  const activeJob = (id: Tab) => (id === 'scan' && scanRunning()) || (id === 'nearby' && nearbyActive()) || (id === 'radio' && bleActive());

  return <div class="app-shell">
    <input ref={input} type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" aria-label="PCAP file" hidden onChange={event => void loadFile(event.currentTarget.files?.[0])} />
    <header class="app-header">
      <Show when={canGoBack()} fallback={<button class="brand" onClick={() => navigateTab('packets')} aria-label="SeekerShark packets"><Icon name="fin" size={24} /><strong>Seeker<span>Shark</span></strong></button>}><button class="back-button app-back" aria-label="Back to previous view" onClick={goBack}><Icon name="back" size={19} /><span>Back</span></button></Show>
      <span class="mode-badge" data-mode={modeLabel()} aria-label={mode() === 'demo' ? 'Demo mode: synthetic packets' : `Capture: ${modeLabel()}`} title={mode() === 'demo' ? 'Synthetic packets' : modeLabel()}>{modeLabel()}</span>
      <span class="version">0.5.0</span>
      <button classList={{ 'capture-button': true, recording: running() }} aria-label={running() ? 'Stop capture' : 'Start capture'} disabled={busy()} onClick={() => void toggleCapture()}><Icon name={running() ? 'stop' : 'play'} size={15} /><span>{busy() ? '…' : running() ? 'Stop' : 'Capture'}</span></button>
    </header>
    <div class="command-bar" classList={{ 'scan-only': tab() === 'scan' || tab() === 'nearby' || tab() === 'radio' }}>
      <nav class="desktop-nav" aria-label="Main navigation"><For each={navItems}>{item => <button classList={{ active: tab() === item.id, 'scan-active': activeJob(item.id) }} aria-current={tab() === item.id ? 'page' : undefined} onClick={() => navigateTab(item.id)}><Icon name={item.icon} size={16} />{item.label}{activeJob(item.id) ? ' •' : ''}</button>}</For></nav>
      <Show when={tab() !== 'scan' && tab() !== 'nearby' && tab() !== 'radio'}><div class="file-actions">
        <button aria-label="Open PCAP" title="Open PCAP" disabled={busy()} onClick={() => input.click()}><Icon name="upload" size={16} /><span>Open</span></button>
        <button aria-label="Export" title="Export PCAP" disabled={busy() || !capture().packets.length} onClick={() => void exportFile()}><Icon name="download" size={16} /><span>Export</span></button>
        <button class="icon-button" aria-label="Clear buffer" title="Clear buffer" disabled={busy() || !capture().packets.length} onClick={() => void clear()}><Icon name="trash" size={16} /><span>Clear</span></button>
      </div>
      <BeautifySwitch enabled={beautify()} onChange={setBeautify} /></Show>
    </div>
    <div class="capture-stats" aria-label="Capture statistics" hidden={tab() === 'scan' || tab() === 'nearby' || tab() === 'radio'}>
      <span><b>{number(capture().packets.length)}</b>/{number(capture().totalPackets)} pkt</span>
      <span>{bytes(capture().totalBytes)}</span><span>{duration()} s</span>
      <span classList={{ loss: capture().droppedPackets > 0 }} title="Queue losses and packets evicted from the ring buffer">drop {number(capture().droppedPackets)}</span>
      <Show when={fileName() && mode() === 'file'}><span class="source-file" title={fileName()}>{fileName()}</span></Show>
      <Show when={running() && capture().totalPackets > 1500}><span title="Latest 1,500 packets; the full retained buffer is available after stopping">view 1,500</span></Show>
    </div>
    <Show when={error()}><div class="message error" role="alert"><Icon name="info" size={15} /><span>{error()}</span><button class="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><Icon name="close" size={15} /></button></div></Show>
    <Show when={notice()}><div class="message notice" role="status"><span title={notice()}>{notice()}</span><button class="icon-button" aria-label="Dismiss notification" onClick={() => setNotice('')}><Icon name="close" size={15} /></button></div></Show>
    <main ref={workspace} class="workspace">
      <Show when={tab() === 'packets'}>
        <section class="packet-panel" aria-label="Packets">
          <div class="filter-row">
            <div class="filter-bar"><Icon name="search" size={16} /><input aria-label="Filter packets" placeholder="proto:DNS port:53 host:…" value={query()} onInput={event => setQuery(event.currentTarget.value)} /><Show when={query()}><button class="icon-button" onClick={() => setQuery('')} aria-label="Clear filter"><Icon name="close" size={14} /></button></Show></div>
            <details ref={filterHelp} class="filter-help" onToggle={event => { if (event.currentTarget === filterHelp) setFilterHelpOpen(event.currentTarget.open); }}><summary aria-label="Filter syntax">?</summary><div><code>proto:TLS port:443<br />host:1.1.1.1<br />DNS names or free text</code><small>AND matching · not Wireshark display filters</small></div></details>
          </div>
          <div class="protocol-filters"><button classList={{ selected: !query() }} onClick={() => setQuery('')}>All</button><For each={protocols().slice(0, 6)}>{protocol => <button classList={{ selected: query().toLowerCase() === `proto:${protocol.name.toLowerCase()}` }} onClick={() => setQuery(`proto:${protocol.name}`)}><i class={`protocol-dot ${tone(protocol.name)}`} />{protocol.name}<span>{protocol.count}</span></button>}</For></div>
          <div class="packet-table" role="table" aria-label="Captured packets">
            <div class="table-head" role="row"><span role="columnheader"># / Δt</span><span role="columnheader">Source → Destination</span><span role="columnheader">Proto</span><span role="columnheader">Bytes</span><span role="columnheader">Info</span></div>
            <For each={filtered().slice(0, limit())}>{packet => <button classList={{ 'packet-row': true, 'readable-row': beautify() }} role="row" onClick={() => void openPacket(packet)} aria-label={`Packet ${packet.id}, ${packet.protocol}, ${packet.source} to ${packet.destination}`}>
              <span class="packet-time" role="cell"><strong>{packet.id}</strong><small>{Math.max(0, packet.timestamp - startTime()).toFixed(3)}</small></span>
              <span class="packet-address" role="cell"><span>{packet.source}<small>{packet.sourcePort != null ? `:${packet.sourcePort}` : ''}</small></span><span class="packet-target">→ {packet.destination}<small>{packet.destinationPort != null ? `:${packet.destinationPort}` : ''}</small></span></span>
              <span class={`protocol-badge ${tone(packet.protocol)}`} role="cell">{packet.protocol}</span>
              <span class="packet-length" role="cell">{number(packet.length)}</span>
              <span class="packet-info" role="cell">{beautify() ? packetSummary(packet) : packet.info}</span>
            </button>}</For>
            <Show when={!filtered().length}><div class="empty-state"><span>{capture().packets.length ? 'No matches' : 'No packets'}</span><Show when={query()}><button class="secondary-button" onClick={() => setQuery('')}>Reset filter</button></Show></div></Show>
          </div>
          <div class="table-footer"><span>{Math.min(limit(), filtered().length)} / {number(filtered().length)}{query() ? ' matches' : ' packets'}</span><Show when={filtered().length > limit()}><button onClick={() => setLimit(value => value + 150)}>+150</button></Show><span>{beautify() ? 'Beautify' : 'Raw'}</span></div>
        </section>
      </Show>
      <Show when={tab() === 'analysis'}>
        <div class="analysis-grid scroll-pane">
          <section class="surface traffic-surface"><div class="panel-heading"><h2>Traffic</h2><span>{duration()} s · Bytes / time bin</span></div><div class="traffic-chart"><svg viewBox="0 0 516 80" preserveAspectRatio="none" aria-label="Packet volume across 44 time bins" role="img"><polyline points={chart()} fill="none" stroke="var(--accent)" stroke-width="1.5" vector-effect="non-scaling-stroke" /></svg></div></section>
          <section class="surface"><div class="panel-heading"><h2>Protocols</h2><span>{number(capture().packets.length)} pkt</span></div><div class="distribution"><Show when={protocols().length} fallback={<p class="section-empty">No packets</p>}><For each={protocols()}>{protocol => <button class="distribution-row" onClick={() => drillDown(`proto:${protocol.name}`)}><span class={`protocol-badge ${tone(protocol.name)}`}>{protocol.name}</span><div class="distribution-track"><span class={tone(protocol.name)} style={{ width: `${protocol.count / capture().packets.length * 100}%` }} /></div><span>{protocol.count}<small>{Math.round(protocol.count / capture().packets.length * 100)}%</small></span></button>}</For></Show></div></section>
          <section class="surface"><div class="panel-heading"><h2>Endpoints</h2><span>Source + Destination</span></div><div class="endpoint-list"><Show when={endpoints().length} fallback={<p class="section-empty">No endpoints</p>}><For each={endpoints()}>{([host, count]) => <div class="endpoint-row"><button onClick={() => drillDown(`host:${host}`)}><code>{host}</code><span>{number(count)} pkt</span><Icon name="arrow" size={14} /></button><button class="endpoint-scan" disabled={scanRunning()} aria-label={`Scan ${host}`} onClick={() => { setScanTarget(host); navigateTab('scan'); }}>Scan</button></div>}</For></Show></div></section>
        </div>
      </Show>
      <Show when={tab() === 'tools'}>
        <div class="session-pane scroll-pane">
          <section class="surface"><div class="panel-heading"><h2>Session</h2><span>{modeLabel()}</span></div><dl class="session-card"><div><dt>Source</dt><dd>{mode() === 'demo' ? 'Demo · synthetic packets' : mode() === 'file' ? fileName() : mode() === 'live' ? 'Android VPN' : '—'}</dd></div><div><dt>Runtime</dt><dd>{native ? 'Android / Tauri' : 'Browser'}</dd></div><div><dt>Linktype</dt><dd>{capture().linkType === 101 ? '101 · Raw IP' : capture().linkType === 1 ? '1 · Ethernet' : capture().linkType}</dd></div><div><dt>View</dt><dd>{number(capture().packets.length)} packets</dd></div><div><dt>Captured</dt><dd>{number(capture().totalPackets)} packets · {bytes(capture().totalBytes)}</dd></div><div><dt>Capture</dt><dd>{running() ? 'Active' : 'Stopped'}</dd></div></dl><div class="session-actions"><button class="secondary-button" disabled={running() || busy()} onClick={loadDemo}>Load demo</button></div></section>
          <details class="surface technical-details"><summary>Capture limits</summary><dl class="session-card"><div><dt>Retention</dt><dd>10.000 packets / 32 MiB</dd></div><div><dt>Live view</dt><dd>Neueste 1.500 packets</dd></div><div><dt>Import</dt><dd>PCAP ≤ 64 MiB · no PCAPNG</dd></div><div><dt>Forwarding</dt><dd>TCP / UDP · no ICMP</dd></div><div><dt>TLS</dt><dd>No decryption</dd></div><div><dt>Android</dt><dd>One VPN per profile</dd></div><div><dt>Analysis</dt><dd>Individual packets · no stream reassembly</dd></div></dl></details>
        </div>
      </Show>
      <ScanPanel active={tab() === 'scan'} native={native} target={scanTarget()} onTarget={setScanTarget} onRunning={setScanRunning} onInspect={host => drillDown(`host:${host}`)} />
      <NearbyPanel active={tab() === 'nearby'} native={native} canShare={native && mode() !== 'demo' && capture().totalPackets > 0 && !busy()} captureRunning={running() || busy()} onActive={setNearbyActive} onImport={openNearbyCapture} />
      <RadioPanel active={tab() === 'radio'} native={native} onActive={setBleActive} />
    </main>
    <nav class="mobile-nav" aria-label="Mobile navigation"><For each={navItems}>{item => <button classList={{ active: tab() === item.id, 'scan-active': activeJob(item.id) }} aria-current={tab() === item.id ? 'page' : undefined} onClick={() => navigateTab(item.id)}><Icon name={item.icon} size={18} /><span>{item.label}{activeJob(item.id) ? ' •' : ''}</span></button>}</For></nav>
    <dialog ref={dialog} class="packet-dialog" onCancel={event => { event.preventDefault(); goBack(); }} onClose={() => { if (selected()) goBack(); }} onClick={event => { if (event.target === dialog) goBack(); }}>
      <Show when={selected()}>{packet => <div class="inspector">
        <div class="inspector-heading"><button class="back-button" aria-label="Back to packet list" onClick={goBack}><Icon name="back" size={20} /><span>Back</span></button><h2>#{packet().id} <span class={`protocol-badge ${tone(packet().protocol)}`}>{packet().protocol}</span></h2></div>
        <div class="packet-route"><code>{endpoint(packet().source, packet().sourcePort)}</code><Icon name="arrow" size={14} /><code>{endpoint(packet().destination, packet().destinationPort)}</code></div>
        <div class="detail-meta"><span>{new Date(packet().timestamp * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC')}</span><span>{number(packet().length)} B{packet().truncated ? ' · truncated' : ''}</span></div>
        <div class="detail-tabs" role="tablist" aria-label="Packet details"><button role="tab" aria-selected={detailTab() === 'layers'} classList={{ active: detailTab() === 'layers' }} onClick={() => setDetailTab('layers')}>Fields</button><button role="tab" aria-selected={detailTab() === 'hex'} classList={{ active: detailTab() === 'hex' }} onClick={() => setDetailTab('hex')}>Hex</button><BeautifySwitch enabled={beautify()} onChange={setBeautify} /></div>
        <div class="detail-content">
          <Show when={detailError()}><p class="detail-error" role="alert">{detailError()}</p></Show>
          <Show when={detailTab() === 'layers'}>
            <Show when={readable()} fallback={<p class="raw-info">{packet().info}</p>}>{view => <div class="readable-summary"><strong>{view().summary}</strong><For each={view().notes}>{note => <p>{note}</p>}</For><Show when={view().payload}>{payload => <section class="readable-payload"><h3>{payload().format}</h3><pre>{payload().text}</pre><small>{payload().note}</small></section>}</Show></div>}</Show>
            <Show when={readable()} fallback={<For each={packet().layers}>{layer => <details open class="protocol-layer"><summary>{layer.name}</summary><dl><For each={layer.fields}>{field => <div><dt>{field.name}</dt><dd>{field.value}</dd></div>}</For></dl></details>}</For>}>{view => <For each={view().layers}>{layer => <details open class="protocol-layer readable-layer"><summary>{layer.name}</summary><dl><For each={layer.fields}>{field => <div><dt>{field.name}</dt><dd>{field.value}<Show when={field.hint}><small>{field.hint}</small></Show></dd></div>}</For></dl></details>}</For>}</Show>
            <Show when={!packet().layers.length && !detailError()}><p class="section-empty">Loading fields …</p></Show>
          </Show>
          <Show when={detailTab() === 'hex'}><p class="hex-caption">{number(Math.min(hexLimit(), packet().hex.replace(/[^a-f0-9]/gi, '').length / 2))} of {number(packet().hex.replace(/[^a-f0-9]/gi, '').length / 2)} Bytes</p><div class="hex-view"><For each={hexLines()}>{line => <div><span>{line.offset}</span><code>{line.hex}</code><code class="hex-ascii">{line.ascii}</code></div>}</For></div><Show when={hexLimit() * 2 < packet().hex.replace(/[^a-f0-9]/gi, '').length}><button class="secondary-button hex-more" onClick={() => setHexLimit(value => value + 256)}>Show 256 more bytes</button></Show><Show when={!hexLines().length}><p class="section-empty">No hex data</p></Show></Show>
        </div>
        <div class="inspector-backbar"><button class="back-button" aria-label="Back to list" onClick={goBack}><Icon name="back" size={19} /><span>Back to list</span></button></div>
      </div>}</Show>
    </dialog>
  </div>;
}
