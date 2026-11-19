import { describe, expect, test } from 'bun:test';
import { beautifyPacket, packetSummary } from '../src/beautify';
import { demoCapture } from '../src/demo';
import type { Packet } from '../src/api';

function packetWithPayload(text: string, options: { ipv6?: boolean; tcpOptions?: boolean; vlan?: boolean } = {}): Packet {
  const data = new TextEncoder().encode(text);
  const ipLength = options.ipv6 ? 48 : 20; // IPv6 includes one 8-byte hop-by-hop header.
  const tcpLength = options.tcpOptions ? 24 : 20;
  const network = new Uint8Array(ipLength + tcpLength + data.length);
  if (options.ipv6) {
    network[0] = 0x60; network[4] = (network.length - 40) >> 8; network[5] = (network.length - 40) & 255;
    network[6] = 0; network[7] = 64; network[40] = 6; network[41] = 0;
  } else {
    network[0] = 0x45; network[2] = network.length >> 8; network[3] = network.length & 255; network[9] = 6;
  }
  network[ipLength + 12] = (tcpLength / 4) << 4;
  network.set(data, ipLength + tcpLength);
  let raw = network;
  if (options.vlan) {
    raw = new Uint8Array(18 + network.length);
    raw.set([0x81, 0, 0, 42, 8, 0], 12); raw.set(network, 18);
  }
  return {
    id: 1, timestamp: 1783150200, source: '10.0.0.1', destination: '192.0.2.10',
    sourcePort: 50000, destinationPort: 8080, protocol: 'HTTP', length: raw.length,
    info: 'HTTP', hex: Array.from(raw, byte => byte.toString(16).padStart(2, '0')).join(' '),
    layers: options.vlan ? [{ name: 'Ethernet II', fields: [] }] : [],
  };
}

describe('Beautify captured packet data', () => {
  test('formats an actual HTTP/JSON packet and preserves header values', () => {
    const packet = packetWithPayload('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":1,"result":{"slot":42}}');
    const view = beautifyPacket(packet);
    expect(view.payload?.format).toBe('HTTP + JSON');
    expect(view.payload?.text).toContain('HTTP/1.1 200 OK');
    expect(view.payload?.text).toContain('  "result": {\n    "slot": 42\n  }');
    expect(view.payload?.note).toContain('no TCP stream reassembly');
  });

  test('locates payload through a VLAN tag and TCP options', () => {
    const packet = packetWithPayload('{"status":"ok"}', { vlan: true, tcpOptions: true });
    expect(beautifyPacket(packet).payload?.text).toBe('{\n  "status": "ok"\n}');
  });

  test('locates payload after IPv6 extension headers', () => {
    const packet = packetWithPayload('{"ipv6":true}', { ipv6: true });
    expect(beautifyPacket(packet).payload?.format).toBe('JSON');
    expect(beautifyPacket(packet).payload?.text).toContain('"ipv6": true');
  });

  test('never presents TLS or QUIC bytes as decrypted JSON', () => {
    for (const protocol of ['TLS', 'QUIC']) {
      const packet = { ...packetWithPayload('{"secret":42}'), protocol };
      expect(beautifyPacket(packet).payload).toBeNull();
      expect(beautifyPacket(packet).notes.join(' ')).toContain('no decryption');
    }
  });

  test('keeps truncated JSON as a captured text fragment instead of repairing it', () => {
    const packet = { ...packetWithPayload('{"id":1'), truncated: true };
    const view = beautifyPacket(packet);
    expect(view.payload?.format).toBe('Text');
    expect(view.payload?.text).toBe('{"id":1');
    expect(view.notes).toContain('This packet capture is truncated.');
    expect(view.payload?.note).toContain('Incomplete packet');
  });

  test('rejects malformed hex, invalid header offsets and noninitial fragments without throwing', () => {
    const packet = packetWithPayload('{"id":1}');
    for (const hex of ['', '123', 'zz', '45', packet.hex.replace(/^45/, '4f'), packet.hex.replace(/^(?:[\da-f]{2} ){6}00 00/, '45 00 00 30 00 00 00 01')]) {
      expect(() => beautifyPacket({ ...packet, hex })).not.toThrow();
      expect(beautifyPacket({ ...packet, hex }).payload).toBeNull();
    }
    expect(beautifyPacket({ ...packet, hex: 'zz' }).payload).toBeNull();
    expect(beautifyPacket({ ...packet, hex: '45' }).payload).toBeNull();
  });

  test('limits printable payload previews without expanding an unbounded document', () => {
    const view = beautifyPacket(packetWithPayload('x'.repeat(20000)));
    expect(view.payload?.text.length).toBe(16384);
    expect(view.payload?.note).toContain('16 KiB');
    const closingBoundary = beautifyPacket(packetWithPayload('{"a":"' + 'x'.repeat(16372) + '"}'));
    expect(closingBoundary.payload?.text.length).toBe(16384);
    expect(closingBoundary.payload?.note).toContain('16 KiB');
  });

  test('uses actual DNS fields and keeps TLS compatibility versions unambiguous', () => {
    const dns = { ...packetWithPayload(''), protocol: 'DNS', layers: [{ name: 'Domain Name System', fields: [
      { name: 'Question', value: 'example.test' }, { name: 'Response', value: 'true' }, { name: 'Response code', value: '3' },
    ] }] };
    expect(packetSummary(dns)).toBe('DNS response · example.test');
    expect(beautifyPacket(dns).layers[0].fields[2].value).toBe('3 · NXDOMAIN');
    const tls = { ...dns, protocol: 'TLS', layers: [{ name: 'Transport Layer Security', fields: [{ name: 'Legacy record version', value: '3.3' }] }] };
    expect(beautifyPacket(tls).layers[0].fields[0].hint).toContain('not the negotiated TLS version');
  });

  test('clips a large UTF-8 preview without rejecting a split final character', () => {
    const view = beautifyPacket(packetWithPayload('x'.repeat(16383) + '€'));
    expect(view.payload?.format).toBe('Text');
    expect(view.payload?.text).toBe('x'.repeat(16383));
    expect(view.payload?.note).toContain('16 KiB');
  });

  test('the explicitly labeled HTTP demo contains actual matching JSON bytes', () => {
    const packet = demoCapture().packets.find(packet => packet.protocol === 'HTTP')!;
    const view = beautifyPacket(packet);
    expect(view.payload?.format).toBe('HTTP + JSON');
    expect(view.payload?.text).toContain('"method": "getSlot"');
    expect(view.notes).toContain('Demo · synthetic packet.');
  });

  test('preserves u64 numbers, exponents, duplicate keys and JSON string escapes exactly', () => {
    const source = '{"lamports":18446744073709551615,"amount":1e999,"same":1,"same":2,"path":"a\\/b"}';
    const view = beautifyPacket(packetWithPayload(source));
    expect(view.payload?.format).toBe('JSON');
    expect(view.payload?.text).toContain('18446744073709551615');
    expect(view.payload?.text).toContain('1e999');
    expect(view.payload?.text).toContain('"same": 1,\n  "same": 2');
    expect(view.payload?.text).toContain('"path": "a\\/b"');
  });

  test('bounds output for deeply nested JSON instead of expanding indentation indefinitely', () => {
    const view = beautifyPacket(packetWithPayload('['.repeat(4000) + '1' + ']'.repeat(4000)));
    expect(view.payload?.format).toBe('JSON');
    expect(view.payload!.text.length).toBeLessThanOrEqual(16384);
    expect(view.payload?.note).toContain('16 KiB');
  });
});
