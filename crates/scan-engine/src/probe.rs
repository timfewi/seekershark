use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(crate) struct Observed {
    pub service: String,
    pub product: String,
    pub banner: String,
}

pub(crate) fn port_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "domain",
        80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 9090 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 | 8443 | 9443 | 10443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        636 => "ldaps",
        853 => "domain-s",
        989 | 990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql",
        1521 => "oracle",
        1883 => "mqtt",
        2049 => "nfs",
        2375 => "docker",
        2376 => "docker-tls",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5671 => "amqps",
        5672 => "amqp",
        5900 => "vnc",
        6379 => "redis",
        8883 => "mqtts",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => return None,
    })
}

pub(crate) async fn detect(mut stream: TcpStream, port: u16, target: &str) -> Option<Observed> {
    if matches!(
        port,
        443 | 465 | 636 | 853 | 989 | 990 | 993 | 995 | 2376 | 5671 | 8443 | 8883 | 9443 | 10443
    ) {
        stream.write_all(&client_hello(target)).await.ok()?;
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.ok()?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[1] != 3 || !(1..=4).contains(&header[2]) || length > 4096 {
            return None;
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.ok()?;
        return tls_response(header[0], &body);
    }
    if matches!(
        port,
        80 | 81 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000 | 9090 | 9200
    ) {
        return http(&mut stream, target).await;
    }
    // Server-first protocols only. Never send arbitrary text to an unknown service.
    let mut bytes = [0; 2048];
    let mut count = 0;
    while count < bytes.len() {
        let read = stream.read(&mut bytes[count..]).await.ok()?;
        if read == 0 {
            break;
        }
        count += read;
        if bytes[..count].contains(&b'\n') || bytes[..count].contains(&0) {
            break;
        }
    }
    identify(&bytes[..count])
}

pub(crate) async fn http(stream: &mut TcpStream, host: &str) -> Option<Observed> {
    // The caller validates host input. CIDR targets use the connected peer's address.
    let host = if host.contains('/') {
        stream.peer_addr().ok()?.ip().to_string()
    } else {
        host.to_owned()
    };
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host
    };
    stream.write_all(format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SeekerShark\r\nConnection: close\r\n\r\n").as_bytes()).await.ok()?;
    let mut bytes = [0; 2048];
    let mut count = 0;
    while count < bytes.len() {
        let read = stream.read(&mut bytes[count..]).await.ok()?;
        if read == 0 {
            break;
        }
        count += read;
        if bytes[..count].windows(4).any(|value| value == b"\r\n\r\n") {
            break;
        }
    }
    identify(&bytes[..count])
}

fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\r' | '\n' | '\t') {
                '.'
            } else {
                character
            }
        })
        .take(limit)
        .collect()
}

pub(crate) fn identify(bytes: &[u8]) -> Option<Observed> {
    let value = String::from_utf8_lossy(bytes);
    let banner = clean(&value, 512);
    let first = value.lines().next().unwrap_or("");
    let (service, product) = if first.starts_with("SSH-") {
        ("ssh", first.splitn(3, '-').nth(2).unwrap_or("").to_owned())
    } else if first.starts_with("HTTP/1.0 ") || first.starts_with("HTTP/1.1 ") {
        (
            "http",
            value
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("server")
                        .then(|| value.trim().to_owned())
                })
                .unwrap_or_default(),
        )
    } else if first.starts_with("220") && first.to_ascii_uppercase().contains("SMTP") {
        ("smtp", first.to_owned())
    } else if first.starts_with("220") && first.to_ascii_uppercase().contains("FTP") {
        ("ftp", first.to_owned())
    } else if first.starts_with("+OK") && first.to_ascii_uppercase().contains("POP") {
        ("pop3", first.to_owned())
    } else if first.to_ascii_uppercase().starts_with("* OK")
        && first.to_ascii_uppercase().contains("IMAP")
    {
        ("imap", first.to_owned())
    } else if first.starts_with("RFB ") {
        ("vnc", first.to_owned())
    } else {
        // Retain a bounded observed banner without guessing the application.
        if banner.trim().is_empty() {
            return None;
        }
        return Some(Observed {
            service: "unknown".into(),
            product: String::new(),
            banner,
        });
    };
    Some(Observed {
        service: service.into(),
        product: clean(&product, 128),
        banner,
    })
}

fn tls_response(record_type: u8, body: &[u8]) -> Option<Observed> {
    if record_type == 21 && body.len() == 2 && matches!(body[0], 1 | 2) {
        return Some(Observed {
            service: "tls".into(),
            product: String::new(),
            banner: format!(
                "TLS alert · level {} · description {}. No application protocol identified.",
                body[0], body[1]
            ),
        });
    }
    if record_type != 22 || body.len() < 42 || body[0] != 2 {
        return None;
    }
    let declared = (body[1] as usize) << 16 | (body[2] as usize) << 8 | body[3] as usize;
    let session = body[38] as usize;
    if session > 32
        || declared + 4 > body.len()
        || declared < 38 + session
        || 41 + session > body.len()
    {
        return None;
    }
    let version = match &body[4..6] {
        [3, 1] => "TLS 1.0",
        [3, 2] => "TLS 1.1",
        [3, 3] => "TLS 1.2",
        _ => return None,
    };
    let cipher = u16::from_be_bytes([body[39 + session], body[40 + session]]);
    Some(Observed { service: "tls".into(), product: version.into(), banner: format!("TLS ServerHello · {version} · cipher 0x{cipher:04x}. TLS 1.2 probe; no application protocol identified.") })
}

fn client_hello(target: &str) -> Vec<u8> {
    // A handshake probe only: no key exchange, encrypted session, or trust decision.
    // TLS 1.3 is not offered; the response cannot be mistaken for a TLS 1.3 negotiation.
    let mut extensions = vec![
        0, 10, 0, 6, 0, 4, 0, 29, 0, 23, 0, 11, 0, 2, 1, 0, 0, 13, 0, 10, 0, 8, 4, 3, 8, 4, 4, 1,
        5, 3,
    ];
    if !target.contains('/') && !target.contains(':') && target.parse::<std::net::IpAddr>().is_err()
    {
        let host = target.as_bytes();
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        extensions.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host);
    }
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0x53; 32]);
    hello.extend_from_slice(&[0, 0, 8, 0xc0, 0x2f, 0xc0, 0x2b, 0, 0x9c, 0, 0x2f, 1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut output = vec![22, 3, 1];
    output.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
    output.extend_from_slice(&[1, 0, (hello.len() >> 8) as u8, hello.len() as u8]);
    output.extend_from_slice(&hello);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_hello_has_consistent_lengths_and_sni() {
        let bytes = client_hello("example.test");
        assert_eq!(
            u16::from_be_bytes([bytes[3], bytes[4]]) as usize,
            bytes.len() - 5
        );
        assert_eq!(
            ((bytes[7] as usize) << 8) | bytes[8] as usize,
            bytes.len() - 9
        );
        assert!(bytes.windows(12).any(|value| value == b"example.test"));
        assert!(!client_hello("127.0.0.1")
            .windows(9)
            .any(|value| value == b"127.0.0.1"));
    }

    #[test]
    fn tls_uses_server_hello_not_the_compatibility_record_version() {
        let mut body = vec![2, 0, 0, 38, 3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
        let result = tls_response(22, &body).unwrap();
        assert_eq!(result.service, "tls");
        assert_eq!(result.product, "TLS 1.2");
        assert!(result.banner.contains("0xc02f"));
        body[38] = 255;
        assert!(tls_response(22, &body).is_none());
        assert!(tls_response(22, &[2, 0, 0]).is_none());
        assert!(tls_response(21, &[2, 70]).unwrap().product.is_empty());
    }

    #[test]
    fn banners_are_evidence_not_port_based_guesses_and_are_bounded() {
        assert_eq!(
            identify(b"SSH-2.0-OpenSSH_9.9\r\n").unwrap().product,
            "OpenSSH_9.9"
        );
        assert_eq!(
            identify(b"HTTP/1.1 200 OK\r\nServer: example/1.0\r\n\r\n")
                .unwrap()
                .service,
            "http"
        );
        assert_eq!(
            identify(b"220 unidentified greeting\r\n").unwrap().service,
            "unknown"
        );
        assert!(identify(b"").is_none());
        assert_eq!(identify(&vec![b'x'; 4096]).unwrap().banner.len(), 512);
        assert!(!identify(b"SSH-2.0-X\x1b[31m")
            .unwrap()
            .banner
            .contains('\x1b'));
    }
}
