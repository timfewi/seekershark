//! Local, bounded packet analysis. This crate never opens sockets or uploads traffic.
//! Dissection is per packet: encrypted contents and TCP stream reassembly are not inferred.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const MAX_PACKET_SIZE: usize = 262_144;
pub const MAX_IMPORT_SIZE: usize = 64 * 1024 * 1024;
const HEX_PREVIEW_BYTES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub name: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Packet {
    pub id: u64,
    /// Unix timestamp in seconds, including the subsecond fraction.
    pub timestamp: f64,
    pub source: String,
    pub destination: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: String,
    /// Original on-wire length; it may exceed captured_length for a snaplen capture.
    pub length: u32,
    pub captured_length: u32,
    pub truncated: bool,
    pub info: String,
    pub layers: Vec<Layer>,
    /// Space separated lowercase bytes, at most 256 bytes unless requesting detail.
    pub hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub packets: Vec<Packet>,
    /// Count of successfully ingested records, including records evicted from the ring.
    pub total_packets: u64,
    pub total_bytes: u64,
    /// Records evicted by the retention limits, not estimated kernel capture drops.
    pub dropped_packets: u64,
    pub link_type: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RawPacket {
    pub timestamp: f64,
    pub data: Vec<u8>,
    pub original_length: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PcapFile {
    pub link_type: u32,
    pub packets: Vec<RawPacket>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EngineError(pub String);

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EngineError {}

type Result<T> = std::result::Result<T, EngineError>;

fn err(message: impl Into<String>) -> EngineError {
    EngineError(message.into())
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn be24(bytes: &[u8], at: usize) -> Option<usize> {
    let b = bytes.get(at..at.checked_add(3)?)?;
    Some(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
}
fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn field(name: &str, value: impl ToString) -> Field {
    Field {
        name: name.into(),
        value: value.to_string(),
    }
}
fn layer(name: &str, fields: Vec<Field>) -> Layer {
    Layer {
        name: name.into(),
        fields,
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(3));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}
fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Decode Ethernet (with up to two VLAN tags), raw IP, or explicit IPv4/IPv6 PCAP records.
/// Invalid/truncated network headers return an error; PacketStore retains them as Malformed.
pub fn decode_packet(id: u64, timestamp: f64, data: &[u8], link_type: u32) -> Result<Packet> {
    if !timestamp.is_finite() || timestamp < 0.0 {
        return Err(err("Invalid packet timestamp"));
    }
    if data.len() > MAX_PACKET_SIZE {
        return Err(err("Packet exceeds the 256 KiB limit"));
    }
    let mut p = Packet {
        id,
        timestamp,
        source: String::new(),
        destination: String::new(),
        source_port: None,
        destination_port: None,
        protocol: "Unknown".into(),
        length: data.len() as u32,
        captured_length: data.len() as u32,
        truncated: false,
        info: String::new(),
        layers: Vec::new(),
        hex: hex(&data[..data.len().min(HEX_PREVIEW_BYTES)]),
    };
    let (network, kind) = match link_type {
        LINKTYPE_ETHERNET => {
            if data.len() < 14 {
                return Err(err("Truncated Ethernet header"));
            }
            p.source = mac(&data[6..12]);
            p.destination = mac(&data[..6]);
            let mut kind = be16(data, 12).unwrap();
            let mut pos = 14;
            let mut fields = vec![
                field("Source", &p.source),
                field("Destination", &p.destination),
            ];
            for _ in 0..2 {
                if kind != 0x8100 && kind != 0x88a8 {
                    break;
                }
                let tag = be16(data, pos).ok_or_else(|| err("Truncated VLAN header"))?;
                kind = be16(data, pos + 2).ok_or_else(|| err("Truncated VLAN header"))?;
                fields.push(field("VLAN ID", tag & 0x0fff));
                pos += 4;
            }
            fields.push(field("EtherType", format!("0x{kind:04x}")));
            p.layers.push(layer("Ethernet II", fields));
            (&data[pos..], kind)
        }
        LINKTYPE_RAW | 12 => {
            let first = *data.first().ok_or_else(|| err("Empty IP packet"))?;
            (
                data,
                match first >> 4 {
                    4 => 0x0800,
                    6 => 0x86dd,
                    _ => 0,
                },
            )
        }
        228 => (data, 0x0800),
        229 => (data, 0x86dd),
        _ => {
            return Err(err(format!(
                "Unsupported PCAP link type {link_type}; use Ethernet or raw IP"
            )))
        }
    };
    match kind {
        0x0800 => decode_ipv4(network, &mut p)?,
        0x86dd => decode_ipv6(network, &mut p)?,
        0x0806 => {
            p.protocol = "ARP".into();
            p.info = "Address Resolution Protocol".into();
            if network.len() >= 28
                && be16(network, 0) == Some(1)
                && be16(network, 2) == Some(0x0800)
                && network[4] == 6
                && network[5] == 4
            {
                let sender = Ipv4Addr::new(network[14], network[15], network[16], network[17]);
                let target = Ipv4Addr::new(network[24], network[25], network[26], network[27]);
                let operation = be16(network, 6).unwrap();
                p.info = match operation {
                    1 => format!("Who has {target}? Tell {sender}"),
                    2 => format!("{sender} is at {}", mac(&network[8..14])),
                    _ => format!("ARP operation {operation}"),
                };
                p.layers.push(layer(
                    "ARP",
                    vec![
                        field("Operation", operation),
                        field("Sender IP", sender),
                        field("Target IP", target),
                    ],
                ));
            }
        }
        _ => {
            p.info = format!("Unsupported network protocol 0x{kind:04x}");
        }
    }
    Ok(p)
}

fn decode_ipv4(data: &[u8], p: &mut Packet) -> Result<()> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return Err(err("Truncated or invalid IPv4 header"));
    }
    let ihl = ((data[0] & 15) as usize) * 4;
    if ihl < 20 || ihl > data.len() {
        return Err(err("Invalid IPv4 header length"));
    }
    let total = be16(data, 2).unwrap() as usize;
    if total < ihl {
        return Err(err("IPv4 total length is smaller than its header"));
    }
    p.source = Ipv4Addr::new(data[12], data[13], data[14], data[15]).to_string();
    p.destination = Ipv4Addr::new(data[16], data[17], data[18], data[19]).to_string();
    p.protocol = "IPv4".into();
    let fragment = be16(data, 6).unwrap();
    let offset = (fragment & 0x1fff) * 8;
    p.layers.push(layer(
        "Internet Protocol v4",
        vec![
            field("Source", &p.source),
            field("Destination", &p.destination),
            field("TTL", data[8]),
            field("Header length", ihl),
            field("Total length", total),
            field("Protocol", data[9]),
            field("Identification", be16(data, 4).unwrap()),
            field("Fragment offset", offset),
            field("More fragments", fragment & 0x2000 != 0),
        ],
    ));
    if total > data.len() {
        p.info = "Truncated IPv4 payload".into();
    }
    if offset != 0 {
        p.info = format!("IPv4 fragment, offset {offset}");
        return Ok(());
    }
    decode_transport(&data[ihl..total.min(data.len())], data[9], p)
}

fn decode_ipv6(data: &[u8], p: &mut Packet) -> Result<()> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return Err(err("Truncated or invalid IPv6 header"));
    }
    p.source = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap()).to_string();
    p.destination = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()).to_string();
    p.protocol = "IPv6".into();
    let payload = be16(data, 4).unwrap() as usize;
    let end = (40 + payload).min(data.len());
    let mut next = data[6];
    let mut at = 40;
    p.layers.push(layer(
        "Internet Protocol v6",
        vec![
            field("Source", &p.source),
            field("Destination", &p.destination),
            field("Hop limit", data[7]),
            field("Payload length", payload),
            field("Next header", next),
        ],
    ));
    if payload == 0 {
        p.info = "IPv6 empty payload or unsupported jumbogram".into();
        return Ok(());
    }
    for _ in 0..8 {
        match next {
            0 | 43 | 60 | 51 => {
                let header = data
                    .get(at..end)
                    .ok_or_else(|| err("Invalid IPv6 extension offset"))?;
                if header.len() < 2 {
                    return Err(err("Truncated IPv6 extension header"));
                }
                let len = if next == 51 {
                    (header[1] as usize + 2) * 4
                } else {
                    (header[1] as usize + 1) * 8
                };
                if len > header.len() {
                    return Err(err("Invalid IPv6 extension header length"));
                }
                p.layers.push(layer(
                    "IPv6 extension",
                    vec![field("Type", next), field("Length", len)],
                ));
                next = header[0];
                at += len;
            }
            44 => {
                let header = data
                    .get(at..at + 8)
                    .filter(|_| at + 8 <= end)
                    .ok_or_else(|| err("Truncated IPv6 fragment header"))?;
                let fragment = be16(header, 2).unwrap();
                next = header[0];
                at += 8;
                if fragment & 0xfff8 != 0 {
                    p.info = format!("IPv6 fragment, offset {}", fragment & 0xfff8);
                    return Ok(());
                }
            }
            50 => {
                p.protocol = "ESP".into();
                p.info = "Encrypted IPsec payload".into();
                return Ok(());
            }
            59 => {
                p.info = "IPv6 no next header".into();
                return Ok(());
            }
            _ => return decode_transport(&data[at..end], next, p),
        }
    }
    p.info = "IPv6 extension header limit reached".into();
    Ok(())
}

fn decode_transport(data: &[u8], protocol: u8, p: &mut Packet) -> Result<()> {
    match protocol {
        6 => {
            p.protocol = "TCP".into();
            if data.len() < 20 {
                p.info = "Truncated TCP header".into();
                return Ok(());
            }
            let offset = ((data[12] >> 4) as usize) * 4;
            if offset < 20 {
                return Err(err("Invalid TCP data offset"));
            }
            let source = be16(data, 0).unwrap();
            let destination = be16(data, 2).unwrap();
            p.source_port = Some(source);
            p.destination_port = Some(destination);
            let flags = [
                (0x02, "SYN"),
                (0x10, "ACK"),
                (0x01, "FIN"),
                (0x04, "RST"),
                (0x08, "PSH"),
                (0x20, "URG"),
                (0x40, "ECE"),
                (0x80, "CWR"),
            ]
            .iter()
            .filter(|(mask, _)| data[13] & mask != 0)
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(", ");
            let seq = be32(data, 4).unwrap();
            let ack = be32(data, 8).unwrap();
            p.info = format!(
                "{source} → {destination} [{flags}] Seq={seq} Ack={ack} Len={}",
                data.len().saturating_sub(offset)
            );
            p.layers.push(layer(
                "Transmission Control Protocol",
                vec![
                    field("Source port", source),
                    field("Destination port", destination),
                    field("Sequence", seq),
                    field("Acknowledgment", ack),
                    field("Flags", &flags),
                    field("Window", be16(data, 14).unwrap()),
                    field("Header length", offset),
                ],
            ));
            if offset > data.len() {
                p.info.push_str(" · truncated options");
                return Ok(());
            }
            let payload = &data[offset..];
            if source == 53 || destination == 53 {
                if let Some(len) = be16(payload, 0) {
                    if payload.len() >= len as usize + 2 {
                        decode_dns(&payload[2..2 + len as usize], p);
                    }
                }
            }
            if p.protocol == "TCP" && !decode_tls(payload, p) {
                decode_http(payload, p);
            }
        }
        17 => {
            p.protocol = "UDP".into();
            if data.len() < 8 {
                p.info = "Truncated UDP header".into();
                return Ok(());
            }
            let source = be16(data, 0).unwrap();
            let destination = be16(data, 2).unwrap();
            let len = be16(data, 4).unwrap() as usize;
            if len < 8 {
                return Err(err("Invalid UDP length"));
            }
            p.source_port = Some(source);
            p.destination_port = Some(destination);
            p.info = format!("{source} → {destination} Len={}", len - 8);
            p.layers.push(layer(
                "User Datagram Protocol",
                vec![
                    field("Source port", source),
                    field("Destination port", destination),
                    field("Length", len),
                ],
            ));
            let payload = &data[8..len.min(data.len())];
            if source == 53 || destination == 53 || source == 5353 || destination == 5353 {
                decode_dns(payload, p);
            }
            if p.protocol == "UDP"
                && (source == 443 || destination == 443)
                && payload.len() >= 6
                && payload[0] & 0xc0 == 0xc0
            {
                let version = be32(payload, 1).unwrap();
                if version == 1 || version == 0x6b3343cf {
                    p.protocol = "QUIC".into();
                    p.info = format!(
                        "QUIC v{} long header · encrypted payload",
                        if version == 1 { 1 } else { 2 }
                    );
                    p.layers.push(layer(
                        "QUIC",
                        vec![
                            field("Version", format!("0x{version:08x}")),
                            field("Note", "Long-header identification only; no decryption"),
                        ],
                    ));
                }
            }
        }
        1 | 58 => {
            p.protocol = if protocol == 1 { "ICMP" } else { "ICMPv6" }.into();
            if data.len() < 4 {
                p.info = "Truncated ICMP header".into();
                return Ok(());
            }
            let name = match (protocol, data[0]) {
                (1, 8) | (58, 128) => "Echo request",
                (1, 0) | (58, 129) => "Echo reply",
                (1, 3) | (58, 1) => "Destination unreachable",
                (1, 11) | (58, 3) => "Time exceeded",
                (58, 135) => "Neighbor solicitation",
                (58, 136) => "Neighbor advertisement",
                _ => "Control message",
            };
            p.info = format!("{name} · type {} code {}", data[0], data[1]);
            p.layers.push(layer(
                &p.protocol,
                vec![
                    field("Type", data[0]),
                    field("Code", data[1]),
                    field("Description", name),
                ],
            ));
        }
        _ => p.info = format!("IP protocol {protocol}"),
    }
    Ok(())
}

fn dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut at = start;
    let mut consumed = 0;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut total = 0;
    for _ in 0..128 {
        let b = *data.get(at)?;
        if b & 0xc0 == 0xc0 {
            let second = *data.get(at + 1)?;
            let target = (((b & 0x3f) as usize) << 8) | second as usize;
            // DNS compression refers to an earlier name; forbidding forward pointers also prevents cycles.
            if target >= at {
                return None;
            }
            if !jumped {
                consumed += 2;
            }
            at = target;
            jumped = true;
            continue;
        }
        if b & 0xc0 != 0 {
            return None;
        }
        at += 1;
        if !jumped {
            consumed += 1;
        }
        if b == 0 {
            return Some((
                if labels.is_empty() {
                    ".".into()
                } else {
                    labels.join(".")
                },
                consumed,
            ));
        }
        let end = at.checked_add(b as usize)?;
        let label = data.get(at..end)?;
        total += b as usize + 1;
        if total > 255 {
            return None;
        }
        // Preserve non-ASCII names as escaped bytes; never interpret them as markup.
        labels.push(
            label
                .iter()
                .map(|b| {
                    if (0x21..=0x7e).contains(b) && *b != b'.' && *b != b'\\' {
                        (*b as char).to_string()
                    } else {
                        format!("\\{b:03}")
                    }
                })
                .collect::<String>(),
        );
        if !jumped {
            consumed += b as usize;
        }
        at = end;
    }
    None
}

fn decode_dns(data: &[u8], p: &mut Packet) {
    if data.len() < 12 {
        return;
    }
    let flags = be16(data, 2).unwrap();
    let questions = be16(data, 4).unwrap();
    let answers = be16(data, 6).unwrap();
    if questions == 0 || questions > 64 {
        return;
    }
    let Some((name, used)) = dns_name(data, 12) else {
        return;
    };
    let Some(kind) = be16(data, 12 + used) else {
        return;
    };
    if be16(data, 14 + used).is_none() {
        return;
    }
    let record = match kind {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        12 => "PTR",
        33 => "SRV",
        65 => "HTTPS",
        _ => "?",
    };
    p.protocol = "DNS".into();
    p.info = format!(
        "{} 0x{:04x} {record} {name}{}",
        if flags & 0x8000 != 0 {
            "Response"
        } else {
            "Query"
        },
        be16(data, 0).unwrap(),
        if flags & 15 != 0 {
            format!(" · RCODE {}", flags & 15)
        } else {
            String::new()
        }
    );
    p.layers.push(layer(
        "Domain Name System",
        vec![
            field(
                "Transaction ID",
                format!("0x{:04x}", be16(data, 0).unwrap()),
            ),
            field("Response", flags & 0x8000 != 0),
            field("Question", name),
            field("Type", format!("{record} ({kind})")),
            field("Questions", questions),
            field("Answers", answers),
            field("Response code", flags & 15),
        ],
    ));
}

fn decode_http(data: &[u8], p: &mut Packet) -> bool {
    const METHODS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
        b"HTTP/1.",
    ];
    if !METHODS.iter().any(|m| data.starts_with(m)) {
        return false;
    }
    let line_end = data
        .iter()
        .take(512)
        .position(|b| *b == b'\n')
        .unwrap_or(data.len().min(512));
    let line = String::from_utf8_lossy(&data[..line_end])
        .trim_end_matches('\r')
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect::<String>();
    p.protocol = "HTTP".into();
    p.info = line.clone();
    p.layers.push(layer(
        "Hypertext Transfer Protocol",
        vec![
            field("Start line", line),
            field("Note", "Plaintext HTTP; body not reassembled"),
        ],
    ));
    true
}

fn tls_sni(hello: &[u8]) -> Option<String> {
    // ClientHello body: legacy version, random, session id, cipher suites, compression, extensions.
    if hello.len() < 35 {
        return None;
    }
    let mut at = 34;
    at += 1 + *hello.get(at)? as usize;
    at += 2 + be16(hello, at)? as usize;
    at += 1 + *hello.get(at)? as usize;
    let extension_end = at.checked_add(2 + be16(hello, at)? as usize)?;
    at += 2;
    if extension_end > hello.len() {
        return None;
    }
    while at + 4 <= extension_end {
        let kind = be16(hello, at)?;
        let len = be16(hello, at + 2)? as usize;
        at += 4;
        let end = at.checked_add(len)?;
        if end > extension_end {
            return None;
        }
        if kind == 0 {
            let list_len = be16(hello, at)? as usize;
            let mut pos = at + 2;
            if pos.checked_add(list_len)? > end {
                return None;
            }
            while pos + 3 <= end {
                let typ = hello[pos];
                let size = be16(hello, pos + 1)? as usize;
                pos += 3;
                let name = hello.get(pos..pos.checked_add(size)?)?;
                if pos + size > end {
                    return None;
                }
                if typ == 0
                    && !name.is_empty()
                    && name.len() <= 253
                    && name
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-')
                {
                    return String::from_utf8(name.to_vec()).ok();
                }
                pos += size;
            }
        }
        at = end;
    }
    None
}

fn decode_tls(data: &[u8], p: &mut Packet) -> bool {
    if data.len() < 5 || !(20..=23).contains(&data[0]) || data[1] != 3 || data[2] > 4 {
        return false;
    }
    let len = be16(data, 3).unwrap() as usize;
    if len > 18_432 {
        return false;
    }
    let kind = match data[0] {
        20 => "Change cipher spec",
        21 => "Alert",
        22 => "Handshake",
        _ => "Application data",
    };
    p.protocol = "TLS".into();
    p.info = format!("TLS {kind} · record {len} bytes");
    let mut fields = vec![
        field("Record type", kind),
        field("Legacy record version", format!("3.{}", data[2])),
        field("Record length", len),
        field("Complete record", data.len() >= 5 + len),
    ];
    if data[0] == 22 && data.len() >= 9 {
        let handshake = match data[5] {
            1 => "Client hello",
            2 => "Server hello",
            11 => "Certificate",
            20 => "Finished",
            _ => "Handshake message",
        };
        fields.push(field("Handshake", handshake));
        p.info = format!("TLS {handshake}");
        if data[5] == 1 {
            let hs_len = be24(data, 6).unwrap();
            if hs_len <= len.saturating_sub(4) && data.len() >= 9 + hs_len {
                if let Some(sni) = tls_sni(&data[9..9 + hs_len]) {
                    p.info = format!("TLS Client hello · {sni}");
                    fields.push(field("Server name (SNI)", sni));
                }
            }
        }
    }
    fields.push(field(
        "Note",
        "Record identification only; encrypted content is not decrypted",
    ));
    p.layers.push(layer("Transport Layer Security", fields));
    true
}

fn supported_link_type(kind: u32) -> bool {
    matches!(kind, 1 | 12 | 101 | 228 | 229)
}

/// Parse classic PCAP (microsecond/nanosecond timestamps, both byte orders).
/// PCAPNG is deliberately rejected instead of being misinterpreted as classic PCAP.
pub fn parse_pcap(bytes: &[u8], max_packets: usize) -> Result<PcapFile> {
    if bytes.len() > MAX_IMPORT_SIZE {
        return Err(err("PCAP exceeds the 64 MiB import limit"));
    }
    if bytes.len() < 24 {
        return Err(err("Truncated PCAP global header"));
    }
    let (little, nano) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            return Err(err(
                "PCAPNG is not supported yet; export classic PCAP from Wireshark",
            ))
        }
        _ => return Err(err("Invalid PCAP magic number")),
    };
    let u16at = |at| {
        let b: [u8; 2] = bytes[at..at + 2].try_into().unwrap();
        if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let u32at = |at| {
        let b: [u8; 4] = bytes[at..at + 4].try_into().unwrap();
        if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    if u16at(4) != 2 || u16at(6) != 4 {
        return Err(err("Unsupported PCAP version; expected 2.4"));
    }
    let snaplen = u32at(16) as usize;
    let link_type = u32at(20) & 0x0000ffff;
    if snaplen == 0 || snaplen > MAX_PACKET_SIZE {
        return Err(err("Unsupported PCAP snapshot length"));
    }
    if !supported_link_type(link_type) {
        return Err(err(format!(
            "Unsupported PCAP link type {link_type}; use Ethernet or raw IP"
        )));
    }
    let mut at: usize = 24;
    let mut packets = Vec::new();
    while at < bytes.len() {
        if packets.len() >= max_packets {
            return Err(err(format!(
                "PCAP exceeds the {max_packets} packet import limit"
            )));
        }
        if bytes.len() - at < 16 {
            return Err(err(format!("Truncated PCAP record header at byte {at}")));
        }
        let sec = u32at(at);
        let fraction = u32at(at + 4);
        let size = u32at(at + 8) as usize;
        let original = u32at(at + 12);
        let divisor = if nano { 1_000_000_000.0 } else { 1_000_000.0 };
        if fraction as f64 >= divisor {
            return Err(err("Invalid PCAP subsecond timestamp"));
        }
        if size > snaplen || size > MAX_PACKET_SIZE || size > original as usize {
            return Err(err("Invalid PCAP record length"));
        }
        at += 16;
        let end = at
            .checked_add(size)
            .ok_or_else(|| err("PCAP length overflow"))?;
        let data = bytes
            .get(at..end)
            .ok_or_else(|| err(format!("Truncated PCAP record payload at byte {at}")))?;
        packets.push(RawPacket {
            timestamp: sec as f64 + fraction as f64 / divisor,
            data: data.to_vec(),
            original_length: original,
        });
        at = end;
    }
    Ok(PcapFile { link_type, packets })
}

/// Write little endian, microsecond-resolution PCAP, preserving captured/original lengths.
pub fn write_pcap(packets: &[RawPacket], link_type: u32) -> Result<Vec<u8>> {
    if !supported_link_type(link_type) {
        return Err(err("Unsupported PCAP link type"));
    }
    let total = packets.iter().try_fold(24usize, |sum, p| {
        sum.checked_add(16 + p.data.len())
            .ok_or_else(|| err("PCAP length overflow"))
    })?;
    if total > MAX_IMPORT_SIZE {
        return Err(err("PCAP export exceeds 64 MiB"));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(MAX_PACKET_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&link_type.to_le_bytes());
    for p in packets {
        if p.data.len() > MAX_PACKET_SIZE || p.data.len() > p.original_length as usize {
            return Err(err("Invalid packet length for PCAP export"));
        }
        if !p.timestamp.is_finite() || p.timestamp < 0.0 || p.timestamp.floor() > u32::MAX as f64 {
            return Err(err("Timestamp cannot be represented in classic PCAP"));
        }
        let sec = p.timestamp.floor() as u32;
        let micros = ((p.timestamp - sec as f64) * 1_000_000.0)
            .round()
            .min(999_999.0) as u32;
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&micros.to_le_bytes());
        out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&p.original_length.to_le_bytes());
        out.extend_from_slice(&p.data);
    }
    Ok(out)
}

struct StoredPacket {
    packet: Packet,
    raw: RawPacket,
}

/// A count- and byte-bounded ring. IPC snapshots omit payload and layer detail.
pub struct PacketStore {
    packets: VecDeque<StoredPacket>,
    capacity: usize,
    byte_limit: usize,
    retained_bytes: usize,
    total_packets: u64,
    total_bytes: u64,
    dropped_packets: u64,
    link_type: u32,
}

impl PacketStore {
    pub fn new(capacity: usize, byte_limit: usize, link_type: u32) -> Result<Self> {
        if capacity == 0 || byte_limit == 0 {
            return Err(err("Packet ring limits must be greater than zero"));
        }
        if !supported_link_type(link_type) {
            return Err(err("Unsupported packet ring link type"));
        }
        Ok(Self {
            packets: VecDeque::new(),
            capacity,
            byte_limit,
            retained_bytes: 0,
            total_packets: 0,
            total_bytes: 0,
            dropped_packets: 0,
            link_type,
        })
    }
    pub fn ingest(&mut self, timestamp: f64, data: &[u8], original_length: u32) -> Result<u64> {
        if data.len() > MAX_PACKET_SIZE || original_length < (data.len() as u32) {
            return Err(err("Invalid captured/original packet length"));
        }
        if !timestamp.is_finite() || timestamp < 0.0 {
            return Err(err("Invalid packet timestamp"));
        }
        let id = self.total_packets.saturating_add(1);
        let mut packet =
            decode_packet(id, timestamp, data, self.link_type).unwrap_or_else(|e| Packet {
                id,
                timestamp,
                source: String::new(),
                destination: String::new(),
                source_port: None,
                destination_port: None,
                protocol: "Malformed".into(),
                length: original_length,
                captured_length: data.len() as u32,
                truncated: original_length > data.len() as u32,
                info: e.to_string(),
                layers: vec![layer("Decode error", vec![field("Reason", e)])],
                hex: hex(&data[..data.len().min(HEX_PREVIEW_BYTES)]),
            });
        packet.length = original_length;
        packet.truncated = original_length > data.len() as u32;
        self.total_packets = id;
        self.total_bytes = self.total_bytes.saturating_add(original_length as u64);
        // Size bound includes the raw allocation and the bounded decoded representation.
        let cost = stored_cost(&packet, data.len());
        while !self.packets.is_empty()
            && (self.packets.len() >= self.capacity
                || self.retained_bytes.saturating_add(cost) > self.byte_limit)
        {
            self.evict();
        }
        if cost > self.byte_limit {
            self.dropped_packets = self.dropped_packets.saturating_add(1);
            return Ok(id);
        }
        self.retained_bytes += cost;
        self.packets.push_back(StoredPacket {
            packet,
            raw: RawPacket {
                timestamp,
                data: data.to_vec(),
                original_length,
            },
        });
        Ok(id)
    }
    fn evict(&mut self) {
        if let Some(p) = self.packets.pop_front() {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(stored_cost(&p.packet, p.raw.data.len()));
            self.dropped_packets = self.dropped_packets.saturating_add(1);
        }
    }
    pub fn snapshot(&self, after_id: u64, limit: usize) -> Capture {
        let packets = self
            .packets
            .iter()
            .filter(|p| p.packet.id > after_id)
            .take(limit.min(10_000))
            .map(|p| {
                let p = &p.packet;
                Packet {
                    id: p.id,
                    timestamp: p.timestamp,
                    source: p.source.clone(),
                    destination: p.destination.clone(),
                    source_port: p.source_port,
                    destination_port: p.destination_port,
                    protocol: p.protocol.clone(),
                    length: p.length,
                    captured_length: p.captured_length,
                    truncated: p.truncated,
                    info: p.info.clone(),
                    layers: Vec::new(),
                    hex: String::new(),
                }
            })
            .collect();
        Capture {
            packets,
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            dropped_packets: self.dropped_packets,
            link_type: self.link_type,
        }
    }
    pub fn packet_detail(&self, id: u64) -> Option<Packet> {
        self.packets.iter().find(|p| p.packet.id == id).map(|p| {
            let mut detail = p.packet.clone();
            detail.hex = hex(&p.raw.data);
            detail
        })
    }
    pub fn export_pcap(&self) -> Result<Vec<u8>> {
        // Borrowed writer path avoids cloning packet payloads during export.
        let total = self.packets.iter().try_fold(24usize, |sum, p| {
            sum.checked_add(16 + p.raw.data.len())
                .ok_or_else(|| err("PCAP length overflow"))
        })?;
        if total > MAX_IMPORT_SIZE {
            return Err(err("PCAP export exceeds 64 MiB"));
        }
        let mut out = write_pcap(&[], self.link_type)?;
        out.reserve(total - 24);
        for stored in &self.packets {
            let p = &stored.raw;
            if p.timestamp.floor() > u32::MAX as f64 {
                return Err(err("Timestamp cannot be represented in classic PCAP"));
            }
            let sec = p.timestamp.floor() as u32;
            let micros = ((p.timestamp - sec as f64) * 1_000_000.0)
                .round()
                .min(999_999.0) as u32;
            out.extend_from_slice(&sec.to_le_bytes());
            out.extend_from_slice(&micros.to_le_bytes());
            out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&p.original_length.to_le_bytes());
            out.extend_from_slice(&p.data);
        }
        Ok(out)
    }
    pub fn import_pcap(
        bytes: &[u8],
        capacity: usize,
        byte_limit: usize,
        max_packets: usize,
    ) -> Result<Self> {
        let file = parse_pcap(bytes, max_packets)?;
        let mut store = Self::new(capacity, byte_limit, file.link_type)?;
        for p in file.packets {
            store.ingest(p.timestamp, &p.data, p.original_length)?;
        }
        Ok(store)
    }
    pub fn clear(&mut self) {
        self.packets.clear();
        self.retained_bytes = 0;
        self.total_packets = 0;
        self.total_bytes = 0;
        self.dropped_packets = 0;
    }
    pub fn retained_len(&self) -> usize {
        self.packets.len()
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
    pub fn link_type(&self) -> u32 {
        self.link_type
    }
}

fn stored_cost(p: &Packet, raw_len: usize) -> usize {
    std::mem::size_of::<StoredPacket>()
        + raw_len
        + p.source.capacity()
        + p.destination.capacity()
        + p.protocol.capacity()
        + p.info.capacity()
        + p.hex.capacity()
        + p.layers.capacity() * std::mem::size_of::<Layer>()
        + p.layers
            .iter()
            .map(|l| {
                l.name.capacity()
                    + l.fields.capacity() * std::mem::size_of::<Field>()
                    + l.fields
                        .iter()
                        .map(|f| f.name.capacity() + f.value.capacity())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

pub fn read_pcap(bytes: &[u8], max_packets: usize) -> Result<Capture> {
    let file = parse_pcap(bytes, max_packets)?;
    let mut store = PacketStore::new(
        max_packets.max(1),
        MAX_IMPORT_SIZE.saturating_mul(2),
        file.link_type,
    )?;
    for p in file.packets {
        store.ingest(p.timestamp, &p.data, p.original_length)?;
    }
    Ok(store.snapshot(0, max_packets))
}

#[cfg(test)]
mod tests;
