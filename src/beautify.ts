import type { Field, Packet } from './api';

export interface ReadableField { name: string; value: string; hint: string }
export interface ReadableLayer { name: string; fields: ReadableField[] }
export interface ReadablePayload { format: string; text: string; note: string }
export interface ReadablePacket {
  summary: string;
  layers: ReadableLayer[];
  notes: string[];
  payload: ReadablePayload | null;
}

const names: Record<string, [string, string]> = {
  Source: ['Source', 'Address of the sender of this packet.'],
  Destination: ['Destination', 'Address of the recipient of this packet.'],
  'Source port': ['Source port', 'Port of the sending application.'],
  'Destination port': ['Destination port', 'Port of the receiving application.'],
  TTL: ['TTL', 'Remaining router hops; reduced along the route.'],
  'Time to live': ['TTL', 'Remaining router hops; reduced along the route.'],
  'Hop limit': ['Hop limit', 'IPv6 limit on remaining router hops.'],
  'Header length': ['Header length', 'Size of this protocol header.'],
  'Total length': ['IP packet size', 'Combined size of the IPv4 header and payload.'],
  'Payload length': ['Payload length', 'IPv6 payload excluding the fixed 40-byte header.'],
  Identification: ['Packet ID', 'IPv4 identifier used to associate fragments.'],
  'Fragment offset': ['Fragment offset', 'Position of this fragment in the original IP packet.'],
  'More fragments': ['More fragments', 'More parts of the same IP packet follow.'],
  Sequence: ['Sequence number', 'Position of the data in the TCP byte stream.'],
  Acknowledgment: ['Acknowledgment number', 'Next expected TCP sequence number when ACK is set.'],
  Flags: ['TCP flags', 'SYN: open · ACK: acknowledge · FIN: close · RST: reset · PSH: data.'],
  Window: ['Receive window', 'TCP window value in the header; any negotiated scaling factor is not applied here.'],
  Question: ['DNS name', 'Requested name from the first DNS question.'],
  Questions: ['DNS questions', 'Number of questions in the DNS header.'],
  Answers: ['DNS answers', 'Number of answers reported by the DNS header.'],
  'Transaction ID': ['DNS ID', 'Identifier used to match a DNS response to its query.'],
  Response: ['DNS response', 'Yes: response · No: query.'],
  'Response code': ['DNS result', 'Result code from the DNS server.'],
  'Start line': ['HTTP start line', 'Request method and target, or HTTP response status.'],
  'Record type': ['TLS record type', '20: change cipher spec · 21: alert · 22: handshake · 23: application data.'],
  'Legacy record version': ['TLS compatibility version', 'This field is not the negotiated TLS version.'],
  'Record length': ['TLS record length', 'Length of the TLS record excluding its 5-byte header.'],
  'Complete record': ['Complete record', 'Whether the entire declared TLS record was captured in this packet.'],
  Handshake: ['TLS handshake', 'Message used to establish the encrypted connection.'],
  'Server name (SNI)': ['Server name (SNI)', 'Server name from the captured ClientHello; it may be absent or protected.'],
  Protocol: ['IP protocol', '6: TCP · 17: UDP · 1: ICMP.'],
  'Next header': ['Next header', 'Protocol or extension header following the IPv6 header.'],
  Length: ['Length', ''], Note: ['Note', ''], Reason: ['Decoder error', ''],
};

function find(packet: Packet, name: string): string | undefined {
  for (const layer of packet.layers) {
    const field = layer.fields.find(field => field.name === name);
    if (field) return field.value;
  }
}

/** Cheap summary for list rows: never decodes packet bytes or infers stream state. */
export function packetSummary(packet: Packet): string {
  if (packet.protocol === 'DNS') {
    const name = find(packet, 'Question') ?? packet.info.match(/(?:query|response)\s+\w+\s+([\w.-]+)/i)?.[1];
    const response = find(packet, 'Response');
    const type = response === 'true' || /response/i.test(packet.info) ? 'DNS response'
      : response === 'false' || /query/i.test(packet.info) ? 'DNS query' : 'DNS';
    return name ? `${type} · ${name}` : type;
  }
  if (packet.protocol === 'TCP') {
    const flags = find(packet, 'Flags') ?? packet.info;
    if (/\bRST\b/.test(flags)) return 'TCP · connection reset';
    if (/\bSYN\b/.test(flags)) return /\bACK\b/.test(flags) ? 'TCP · SYN/ACK, connection response' : 'TCP · SYN, opening connection';
    if (/\bFIN\b/.test(flags)) return 'TCP · FIN, closing connection';
    if (/\bACK\b/.test(flags)) return 'TCP · ACK, receipt acknowledged';
    return 'TCP segment';
  }
  if (packet.protocol === 'TLS') {
    const server = find(packet, 'Server name (SNI)');
    if (server) return `TLS handshake · ${server}`;
    if (find(packet, 'Record type') === '22' || /Handshake|ClientHello|ServerHello/i.test(packet.info)) return 'TLS handshake';
    return find(packet, 'Record type') === '23' || /application/i.test(packet.info)
      ? 'TLS application data · encrypted' : 'TLS record';
  }
  if (packet.protocol === 'QUIC') return 'QUIC candidate · UDP, no decryption';
  if (packet.protocol === 'HTTP') return find(packet, 'Start line') ?? packet.info;
  if (packet.protocol === 'UDP') return `UDP datagram · ${packet.sourcePort ?? '?'} → ${packet.destinationPort ?? '?'}`;
  return packet.info || packet.protocol;
}

function readableField(field: Field, layer: string): ReadableField {
  const dns = /DNS|Domain Name System/.test(layer);
  const [name, hint] = dns && field.name === 'Type'
    ? ['DNS type', 'A: IPv4 address · AAAA: IPv6 address · CNAME: alias · MX: mail server.']
    : names[field.name] ?? [field.name, ''];
  let value = field.value;
  if (['true', 'false'].includes(value)) value = value === 'true' ? 'Yes' : 'No';
  if (/^(Header length|Total length|Payload length|Record length|Length|Window|Fragment offset)$/.test(field.name) && /^\d+$/.test(value)) value += ' B';
  if (dns && field.name === 'Response code') {
    const code = ({ '0': 'NOERROR', '1': 'FORMERR', '2': 'SERVFAIL', '3': 'NXDOMAIN', '4': 'NOTIMP', '5': 'REFUSED' } as Record<string, string>)[value];
    if (code) value += ` · ${code}`;
  }
  return { name, value, hint };
}

function layerName(name: string): string {
  return name.replace('Internet Protocol v4', 'IPv4').replace('Internet Protocol v6', 'IPv6')
    .replace('Transmission Control Protocol', 'TCP').replace('User Datagram Protocol', 'UDP')
    .replace('Domain Name System', 'DNS').replace('Transport Layer Security', 'TLS');
}

interface PayloadBytes { data: Uint8Array; incomplete: boolean }
function payloadBytes(packet: Packet): PayloadBytes | null {
  const hex = packet.hex.replace(/\s/g, '');
  if (!hex || hex.length % 2 || /[^\da-f]/i.test(hex)) return null;
  const bytes = Uint8Array.from(hex.slice(0, 131072).match(/../g) ?? [], value => parseInt(value, 16));
  let at = 0;
  if (packet.layers.some(layer => layer.name.startsWith('Ethernet'))) {
    if (bytes.length < 14) return null;
    let type = bytes[12] * 256 + bytes[13]; at = 14;
    for (let n = 0; n < 2 && (type === 0x8100 || type === 0x88a8); n++) {
      if (at + 4 > bytes.length) return null;
      type = bytes[at + 2] * 256 + bytes[at + 3]; at += 4;
    }
    if (type !== 0x0800 && type !== 0x86dd) return null;
  }
  const u16 = (offset: number) => bytes[offset] * 256 + bytes[offset + 1];
  let protocol: number;
  let end: number;
  let fragmented = false;
  if (bytes[at] >> 4 === 4) {
    if (at + 20 > bytes.length) return null;
    const header = (bytes[at] & 15) * 4, total = u16(at + 2), fragment = u16(at + 6);
    if (header < 20 || total < header || at + header > bytes.length || fragment & 0x1fff) return null;
    fragmented = Boolean(fragment & 0x2000);
    end = at + total; protocol = bytes[at + 9]; at += header;
  } else if (bytes[at] >> 4 === 6) {
    if (at + 40 > bytes.length) return null;
    end = at + 40 + u16(at + 4); protocol = bytes[at + 6]; at += 40;
    for (let n = 0; n < 8 && [0, 43, 60, 51, 44].includes(protocol); n++) {
      if (at + 2 > Math.min(end, bytes.length)) return null;
      const next = bytes[at];
      const length = protocol === 44 ? 8 : protocol === 51 ? (bytes[at + 1] + 2) * 4 : (bytes[at + 1] + 1) * 8;
      if (at + length > Math.min(end, bytes.length)) return null;
      if (protocol === 44) {
        const fragment = u16(at + 2);
        if (fragment & 0xfff8) return null;
        fragmented = Boolean(fragment & 1);
      }
      at += length; protocol = next;
    }
  } else return null;
  if (protocol === 6) {
    if (at + 20 > Math.min(end, bytes.length)) return null;
    const length = (bytes[at + 12] >> 4) * 4;
    if (length < 20 || at + length > Math.min(end, bytes.length)) return null;
    at += length;
  } else if (protocol === 17) {
    if (at + 8 > Math.min(end, bytes.length)) return null;
    const length = u16(at + 4);
    if (length < 8 || at + length > end) return null;
    end = at + length; at += 8;
  } else return null;
  return { data: bytes.slice(at, Math.min(end, bytes.length)), incomplete: Boolean(packet.truncated || fragmented || end > bytes.length) };
}

function readablePayload(packet: Packet): ReadablePayload | null {
  // Handshakes and encrypted/binary protocols must not be presented as decrypted text.
  if (['TLS', 'QUIC', 'DNS', 'ESP', 'ICMP', 'ICMPv6', 'Malformed'].includes(packet.protocol)) return null;
  const payload = payloadBytes(packet);
  if (!payload?.data.length) return null;
  const limited = payload.data.length > 16384;
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(payload.data.slice(0, 16384), { stream: limited }); }
  catch { return null; }
  if (/[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]/.test(text)) return null;
  let format = 'Text';
  const http = /^(?:[A-Z]+\s+\S+\s+HTTP\/\d|HTTP\/\d)/.test(text);
  const separator = text.indexOf('\r\n\r\n');
  const body = http ? separator >= 0 ? text.slice(separator + 4) : '' : text;
  if (http) format = 'HTTP';
  let formattedCropped = false;
  if (!payload.incomplete && !limited && /^[\s]*[\[{]/.test(body)) {
    try {
      const pretty = prettyJson(body);
      text = http ? `${text.slice(0, separator)}\n\n${pretty.text}` : pretty.text;
      formattedCropped = pretty.cropped;
      format = http ? 'HTTP + JSON' : 'JSON';
    } catch { /* Incomplete or non-JSON text stays byte-for-byte readable. */ }
  }
  const cropped = text.length > 16384 || limited || formattedCropped;
  return { format, text: text.slice(0, 16384), note: [
    payload.incomplete ? 'Incomplete packet or IP fragment.' : '',
    cropped ? 'Text preview limited to 16 KiB.' : '',
    ['TCP', 'HTTP'].includes(packet.protocol) ? 'Single packet; no TCP stream reassembly.' : 'Single UDP datagram.',
  ].filter(Boolean).join(' ') };
}

/** Whitespace-only formatting: retain u64 numbers, duplicate keys and escapes. */
function prettyJson(source: string): { text: string; cropped: boolean } {
  JSON.parse(source); // Validate syntax; never serialize the parsed JS numbers.
  const tokens = source.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)!;
  const chunks: string[] = [];
  let length = 0, depth = 0, cropped = false;
  const append = (text: string) => { const part = text.slice(0, 16384 - length); if (part.length < text.length) cropped = true; chunks.push(part); length += part.length; };
  const newline = () => append('\n' + '  '.repeat(Math.min(depth, 8192)));
  for (let at = 0; at < tokens.length; at++) {
    const token = tokens[at];
    if (token === '{' || token === '[') {
      append(token); depth++;
      if (tokens[at + 1] !== (token === '{' ? '}' : ']')) newline();
    } else if (token === '}' || token === ']') {
      depth--;
      if (tokens[at - 1] !== (token === '}' ? '{' : '[')) newline();
      append(token);
    } else if (token === ',') { append(','); newline(); }
    else if (token === ':') append(': ');
    else append(token);
    if (length >= 16384 && at < tokens.length - 1) return { text: chunks.join(''), cropped: true };
  }
  return { text: chunks.join(''), cropped };
}

export function beautifyPacket(packet: Packet): ReadablePacket {
  const notes: string[] = [];
  if (packet.protocol === 'TLS' || packet.protocol === 'QUIC') notes.push('Application data is encrypted; no decryption.');
  if (packet.protocol === 'QUIC') notes.push('QUIC detection uses a heuristic.');
  if (packet.truncated) notes.push('This packet capture is truncated.');
  if (packet.layers.some(layer => /example/.test(layer.name))) notes.push('Demo · synthetic packet.');
  return {
    summary: packetSummary(packet), notes,
    layers: packet.layers.map(layer => ({ name: layerName(layer.name), fields: layer.fields.map(field => readableField(field, layer.name)) })),
    payload: readablePayload(packet),
  };
}
