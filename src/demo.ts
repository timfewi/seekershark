import type { Capture, Packet } from './api';

const endpoint = [
  ['DNS', '1.1.1.1', 53, 'Standard query A api.mainnet-beta.solana.com'],
  ['TCP', '104.18.26.145', 443, 'SYN · opening connection'],
  ['TLS', '104.18.26.145', 443, 'TLS record · encrypted application traffic'],
  ['QUIC', '142.250.184.14', 443, 'UDP/443 · possible QUIC traffic'],
  ['DNS', '1.1.1.1', 53, 'Standard query A arweave.net'],
  ['TCP', '172.67.74.144', 443, 'ACK · connection acknowledged'],
  ['TLS', '172.67.74.144', 443, 'TLS record · encrypted application traffic'],
  ['UDP', '162.159.200.1', 123, 'Network Time Protocol'],
] as const;
// Fixed, local examples. No live-looking timers or invented measurements.
export function demoCapture(): Capture {
  const packets: Packet[] = Array.from({ length: 32 }, (_, index) => {
    const httpExample = index === 31;
    const entry = endpoint[index % endpoint.length];
    const protocol = httpExample ? 'HTTP' : entry[0];
    const remote = httpExample ? '192.0.2.10' : entry[1];
    const port = httpExample ? 8080 : entry[2];
    const info = httpExample ? 'POST /rpc HTTP/1.1' : entry[3];
    const json = '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}';
    const request = new TextEncoder().encode(`POST /rpc HTTP/1.1\r\nHost: rpc.example.test\r\nContent-Type: application/json\r\nContent-Length: ${json.length}\r\n\r\n${json}`);
    const incoming = index % 3 === 2;
    const size = httpExample ? 40 + request.length : protocol === 'DNS' ? 76 : protocol === 'TLS' ? 1200 + index * 3 : 60 + index * 4;
    const sourcePort = protocol === 'DNS' ? 53012 : 49820 + index;
    const source = incoming ? remote : '10.23.0.2';
    const destination = incoming ? '10.23.0.2' : remote;
    const raw = new Uint8Array(size);
    raw.set([0x45, 0, size >> 8, size & 255, 0, index, 0x40, 0, 64, protocol === 'UDP' || protocol === 'DNS' || protocol === 'QUIC' ? 17 : 6, 0, 0]);
    raw.set(source.split('.').map(Number), 12); raw.set(destination.split('.').map(Number), 16);
    const srcPort = incoming ? port : sourcePort; const dstPort = incoming ? sourcePort : port;
    raw[20] = srcPort >> 8; raw[21] = srcPort & 255; raw[22] = dstPort >> 8; raw[23] = dstPort & 255;
    if (raw[9] === 17) { raw[24] = (size - 20) >> 8; raw[25] = (size - 20) & 255; }
    else { raw[32] = 0x50; raw[33] = protocol === 'TCP' && !incoming ? 0x02 : 0x10; }
    if (httpExample) raw.set(request, 40);
    if (protocol === 'TLS') { raw.set([0x17, 0x03, 0x03, (size - 45) >> 8, (size - 45) & 255], 40); }
    if (protocol === 'DNS') {
      raw.set([0x12, index, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0], 28);
      const host = index % 8 === 0 ? 'api.mainnet-beta.solana.com' : 'arweave.net';
      let at = 40;
      for (const label of host.split('.')) { raw[at++] = label.length; for (const char of label) raw[at++] = char.charCodeAt(0); }
      raw.set([0, 0, 1, 0, 1], at);
    }
    let sum = 0; for (let n = 0; n < 20; n += 2) sum += (raw[n] << 8) | raw[n + 1];
    while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
    raw[10] = (~sum >>> 8) & 255; raw[11] = ~sum & 255;
    return {
      id: index + 1, timestamp: 1783150200 + index * .146, source, destination,
      sourcePort: incoming ? port : sourcePort, destinationPort: incoming ? sourcePort : port,
      protocol, length: size, info,
      layers: [
        { name: 'Internet Protocol v4', fields: [{ name: 'Source', value: source }, { name: 'Destination', value: destination }, { name: 'Time to live', value: '64' }, { name: 'Length', value: `${size} Bytes` }] },
        { name: ['DNS', 'QUIC', 'UDP'].includes(protocol) ? 'User Datagram Protocol' : 'Transmission Control Protocol', fields: [{ name: 'Source port', value: String(incoming ? port : sourcePort) }, { name: 'Destination port', value: String(incoming ? sourcePort : port) }] },
        { name: `${protocol} · example`, fields: [...(httpExample ? [{ name: 'Start line', value: info }] : []), { name: 'Note', value: info }, { name: 'Data source', value: 'Synthetic local example, not a real capture' }] },
      ],
      hex: Array.from(raw, byte => byte.toString(16).padStart(2, '0')).join(''),
    };
  });
  return { packets, totalPackets: packets.length, totalBytes: packets.reduce((sum, packet) => sum + packet.length, 0), droppedPackets: 0, linkType: 101 };
}

export function demoPcap(capture: Capture): Uint8Array {
  const packets = capture.packets.map(packet => Uint8Array.from(packet.hex.match(/.{2}/g) ?? [], byte => parseInt(byte, 16)));
  const output = new Uint8Array(24 + packets.reduce((sum, packet) => sum + 16 + packet.length, 0));
  const view = new DataView(output.buffer);
  view.setUint32(0, 0xa1b2c3d4, true); view.setUint16(4, 2, true); view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true); view.setUint32(20, 101, true);
  let offset = 24;
  packets.forEach((packet, index) => {
    const timestamp = capture.packets[index].timestamp;
    view.setUint32(offset, Math.floor(timestamp), true);
    view.setUint32(offset + 4, Math.round((timestamp % 1) * 1e6), true);
    view.setUint32(offset + 8, packet.length, true); view.setUint32(offset + 12, packet.length, true);
    output.set(packet, offset + 16); offset += 16 + packet.length;
  });
  return output;
}
