use super::*;

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((payload.len() + 20) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    packet.extend_from_slice(payload);
    packet
}
fn udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 8];
    packet[..2].copy_from_slice(&source.to_be_bytes());
    packet[2..4].copy_from_slice(&destination.to_be_bytes());
    packet[4..6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
fn tcp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[..2].copy_from_slice(&source.to_be_bytes());
    packet[2..4].copy_from_slice(&destination.to_be_bytes());
    packet[12] = 0x50;
    packet[13] = 0x18;
    packet[14..16].copy_from_slice(&65535u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
fn dns() -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    packet
}
fn raw(data: Vec<u8>) -> RawPacket {
    let original_length = data.len() as u32;
    RawPacket {
        timestamp: 1_700_000_000.123456,
        data,
        original_length,
    }
}

#[test]
fn decodes_dns_question_and_layers() {
    let p = decode_packet(7, 12.0, &ipv4(17, &udp(53000, 53, &dns())), LINKTYPE_RAW).unwrap();
    assert_eq!(p.id, 7);
    assert_eq!(p.source, "10.0.0.2");
    assert_eq!(p.destination, "1.1.1.1");
    assert_eq!(p.source_port, Some(53000));
    assert_eq!(p.destination_port, Some(53));
    assert_eq!(p.protocol, "DNS");
    assert!(p.info.contains("example.com"));
    assert_eq!(p.layers.len(), 3);
}

#[test]
fn decodes_http_without_assuming_port() {
    let data = ipv4(
        6,
        &tcp(
            45500,
            8080,
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
    );
    let p = decode_packet(1, 0.0, &data, 101).unwrap();
    assert_eq!(p.protocol, "HTTP");
    assert_eq!(p.info, "GET /health HTTP/1.1");
    assert_eq!(p.layers.last().unwrap().name, "Hypertext Transfer Protocol");
}

#[test]
fn tls_hello_sni_is_bounded_and_not_decrypted() {
    let hostname = b"rpc.solana.com";
    let mut sni = Vec::new();
    sni.extend_from_slice(&((hostname.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    sni.extend_from_slice(hostname);
    let mut extension = vec![0, 0];
    extension.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extension.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension);
    let mut handshake = vec![
        1,
        0,
        ((body.len() >> 8) & 255) as u8,
        (body.len() & 255) as u8,
    ];
    handshake.extend_from_slice(&body);
    let mut tls = vec![22, 3, 1];
    tls.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    tls.extend_from_slice(&handshake);
    let p = decode_packet(1, 0.0, &ipv4(6, &tcp(48000, 443, &tls)), 101).unwrap();
    assert_eq!(p.protocol, "TLS");
    assert_eq!(p.info, "TLS Client hello · rpc.solana.com");
    assert!(p
        .layers
        .last()
        .unwrap()
        .fields
        .iter()
        .any(|f| f.name == "Server name (SNI)" && f.value == "rpc.solana.com"));
    for end in 0..tls.len() {
        let _ = decode_packet(1, 0.0, &ipv4(6, &tcp(48000, 443, &tls[..end])), 101);
    }
}

#[test]
fn decodes_ipv6_extension_then_udp() {
    let udp = udp(1000, 2000, b"hello");
    let mut data = vec![0u8; 40];
    data[0] = 0x60;
    data[4..6].copy_from_slice(&((8 + udp.len()) as u16).to_be_bytes());
    data[6] = 0;
    data[7] = 64;
    data[23] = 1;
    data[39] = 2;
    data.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&udp);
    let p = decode_packet(1, 0.0, &data, 101).unwrap();
    assert_eq!(p.source, "::1");
    assert_eq!(p.destination, "::2");
    assert_eq!(p.protocol, "UDP");
    assert_eq!(p.source_port, Some(1000));
    assert_eq!(p.layers.len(), 3);
}

#[test]
fn fragments_are_not_misread_as_tcp() {
    let mut data = ipv4(6, &[0u8; 20]);
    data[6..8].copy_from_slice(&2u16.to_be_bytes());
    let p = decode_packet(1, 0.0, &data, 101).unwrap();
    assert_eq!(p.protocol, "IPv4");
    assert!(p.source_port.is_none());
    assert!(p.info.contains("fragment"));
}

#[test]
fn ethernet_vlan_is_decoded() {
    let mut data = vec![0xff; 6];
    data.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    data.extend_from_slice(&[0x81, 0, 0, 7, 8, 0]);
    data.extend_from_slice(&ipv4(17, &udp(53000, 53, &dns())));
    let p = decode_packet(1, 0.0, &data, 1).unwrap();
    assert_eq!(p.protocol, "DNS");
    assert!(p.layers[0]
        .fields
        .iter()
        .any(|f| f.name == "VLAN ID" && f.value == "7"));
}

#[test]
fn quic_only_identifies_known_long_header_versions() {
    let p = decode_packet(
        1,
        0.0,
        &ipv4(17, &udp(1000, 443, &[0xc0, 0, 0, 0, 1, 0])),
        101,
    )
    .unwrap();
    assert_eq!(p.protocol, "QUIC");
    let p = decode_packet(
        1,
        0.0,
        &ipv4(17, &udp(1000, 443, &[0xc0, 0, 0, 0, 99, 0])),
        101,
    )
    .unwrap();
    assert_eq!(p.protocol, "UDP");
}

#[test]
fn pcap_roundtrip_preserves_payload_and_timestamps() {
    let records = vec![
        raw(ipv4(17, &udp(53000, 53, &dns()))),
        raw(ipv4(6, &tcp(12000, 443, b"test"))),
    ];
    let bytes = write_pcap(&records, 101).unwrap();
    let file = parse_pcap(&bytes, 10).unwrap();
    assert_eq!(file.link_type, 101);
    assert_eq!(file.packets.len(), 2);
    for (a, b) in records.iter().zip(&file.packets) {
        assert_eq!(a.data, b.data);
        assert!((a.timestamp - b.timestamp).abs() < 0.000002);
        assert_eq!(a.original_length, b.original_length);
    }
    let capture = read_pcap(&bytes, 10).unwrap();
    assert_eq!(capture.total_packets, 2);
    assert_eq!(capture.packets[0].protocol, "DNS");
}

#[test]
fn parses_big_endian_nanosecond_pcap() {
    let data = ipv4(17, &udp(12, 34, b"hi"));
    let mut pcap = vec![0xa1, 0xb2, 0x3c, 0x4d];
    pcap.extend_from_slice(&2u16.to_be_bytes());
    pcap.extend_from_slice(&4u16.to_be_bytes());
    for value in [
        0u32,
        0,
        65535,
        101,
        123,
        500_000_000,
        data.len() as u32,
        data.len() as u32,
    ] {
        pcap.extend_from_slice(&value.to_be_bytes());
    }
    pcap.extend_from_slice(&data);
    let file = parse_pcap(&pcap, 10).unwrap();
    assert_eq!(file.packets[0].timestamp, 123.5);
    assert_eq!(file.packets[0].data, data);
}

#[test]
fn rejects_corrupt_records_and_pcapng() {
    let mut bytes = write_pcap(&[raw(ipv4(17, &udp(1, 2, b"hi")))], 101).unwrap();
    for cut in 1..bytes.len() {
        if cut != 24 {
            assert!(parse_pcap(&bytes[..cut], 10).is_err(), "accepted cut {cut}");
        }
    }
    bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_pcap(&bytes, 10).is_err());
    let mut bytes = vec![0u8; 24];
    bytes[..4].copy_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);
    assert!(parse_pcap(&bytes, 10).unwrap_err().0.contains("PCAPNG"));
}

#[test]
fn pcap_limits_are_explicit_not_silent() {
    let bytes = write_pcap(&[raw(vec![0x45; 20]), raw(vec![0x45; 20])], 101).unwrap();
    assert!(parse_pcap(&bytes, 1)
        .unwrap_err()
        .0
        .contains("packet import limit"));
}

#[test]
fn ring_evicts_by_count_and_keeps_monotonic_ids() {
    let data = ipv4(17, &udp(1, 2, b"hi"));
    let mut store = PacketStore::new(2, 1_000_000, 101).unwrap();
    for _ in 0..4 {
        store.ingest(1.0, &data, data.len() as u32).unwrap();
    }
    let c = store.snapshot(0, 10);
    assert_eq!(c.total_packets, 4);
    assert_eq!(c.dropped_packets, 2);
    assert_eq!(
        c.packets.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert!(store.packet_detail(1).is_none());
    assert!(c.packets[0].hex.is_empty());
    assert!(c.packets[0].layers.is_empty());
    assert!(!store.packet_detail(3).unwrap().hex.is_empty());
    assert_eq!(store.snapshot(3, 1).packets[0].id, 4);
    assert_eq!(
        parse_pcap(&store.export_pcap().unwrap(), 10)
            .unwrap()
            .packets
            .len(),
        2
    );
}

#[test]
fn ring_evicts_by_memory_and_preserves_original_lengths() {
    let mut data = ipv4(17, &udp(1, 2, b"hi"));
    data.resize(500, 0);
    let mut store = PacketStore::new(100, 4000, 101).unwrap();
    for _ in 0..100 {
        store.ingest(1.0, &data, 800).unwrap();
        assert!(store.retained_bytes() <= 4000);
    }
    let c = store.snapshot(0, 100);
    assert!(c.packets.len() < 100);
    assert_eq!(c.total_packets, 100);
    assert_eq!(c.total_bytes, 80_000);
    assert!(c
        .packets
        .iter()
        .all(|p| p.truncated && p.length == 800 && p.captured_length == 500));
    let output = parse_pcap(&store.export_pcap().unwrap(), 100).unwrap();
    assert!(output
        .packets
        .iter()
        .all(|p| p.original_length == 800 && p.data.len() == 500));
}

#[test]
fn retains_malformed_records_for_inspection() {
    let mut store = PacketStore::new(10, 10_000, 101).unwrap();
    store.ingest(1.0, &[0x45], 1).unwrap();
    assert_eq!(store.snapshot(0, 10).packets[0].protocol, "Malformed");
    assert_eq!(store.packet_detail(1).unwrap().hex, "45");
}

#[test]
fn malformed_inputs_never_panic() {
    let fixtures = [
        ipv4(17, &udp(53000, 53, &dns())),
        ipv4(6, &tcp(1000, 80, b"GET / HTTP/1.1\r\n")),
        vec![0xff; 512],
        vec![0; 512],
    ];
    for fixture in fixtures {
        for cut in 0..fixture.len() {
            for link in [1, 101, 228, 229] {
                let _ = decode_packet(1, 1.0, &fixture[..cut], link);
            }
        }
    }
    // Deterministic noise also exercises nested parser lengths without a fuzz dependency.
    let mut seed = 7u64;
    for size in 0..1024 {
        let mut data = vec![0u8; size];
        for b in &mut data {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (seed >> 32) as u8;
        }
        for link in [1, 101, 228, 229] {
            let _ = decode_packet(1, 1.0, &data, link);
        }
    }
}

#[test]
fn cyclic_dns_compression_cannot_loop() {
    let mut message = dns();
    message[12] = 0xc0;
    message[13] = 12;
    let p = decode_packet(1, 0.0, &ipv4(17, &udp(53000, 53, &message)), 101).unwrap();
    assert_eq!(p.protocol, "UDP");
    message[13] = 0xff;
    let _ = decode_packet(1, 0.0, &ipv4(17, &udp(53000, 53, &message)), 101);
}

#[test]
fn hex_preview_and_on_demand_detail_differ() {
    let data = ipv4(17, &udp(1, 2, &[0u8; 1024]));
    let p = decode_packet(1, 0.0, &data, 101).unwrap();
    assert_eq!(p.hex.split_whitespace().count(), 256);
    let mut store = PacketStore::new(10, 100_000, 101).unwrap();
    store.ingest(1.0, &data, data.len() as u32).unwrap();
    assert_eq!(
        store
            .packet_detail(1)
            .unwrap()
            .hex
            .split_whitespace()
            .count(),
        data.len()
    );
}

#[test]
fn rejects_nonfinite_time_and_invalid_lengths() {
    assert!(decode_packet(1, f64::NAN, &[], 101).is_err());
    assert!(write_pcap(
        &[RawPacket {
            timestamp: f64::INFINITY,
            data: vec![],
            original_length: 0
        }],
        101
    )
    .is_err());
    let mut store = PacketStore::new(1, 1000, 101).unwrap();
    assert!(store.ingest(0.0, &[0; 10], 1).is_err());
}
