use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn request(port: u16) -> ScanRequest {
    ScanRequest {
        target: "127.0.0.1".into(),
        ports: port.to_string(),
        concurrency: 4,
        timeout_ms: 500,
        service_detection: false,
        probe_timeout_ms: 500,
    }
}
async fn done(scanner: &Scanner) -> ScanSnapshot {
    timeout(Duration::from_secs(5), async {
        loop {
            let value = scanner.snapshot(MAX_RESULTS).unwrap();
            if !value.phase.active() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("scan must finish")
}

#[test]
fn ports_support_deduplicated_lists_and_full_range_and_reject_invalid_input() {
    assert_eq!(
        parse_ports("443,22,80-82,22").unwrap(),
        vec![22, 80, 81, 82, 443]
    );
    assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
    for input in [
        "",
        "0",
        "65536",
        "10-1",
        "80,",
        "22-",
        "x",
        "1-2-3",
        "-1",
        "1-65535,x",
    ] {
        assert!(parse_ports(input).is_err(), "{input}");
    }
    assert!(parse_ports(&"1,".repeat(5000)).is_err());
}

#[tokio::test]
async fn connects_to_real_ipv6_loopback_and_resolves_localhost() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scanner = Scanner::default();
    scanner
        .start(ScanRequest {
            target: "[::1]".into(),
            ..request(port)
        })
        .unwrap();
    let data = done(&scanner).await;
    assert_eq!(data.open, 1);
    assert_eq!(data.results[0].address, "::1".parse::<IpAddr>().unwrap());
    let addresses = resolve(Target::Hostname("localhost".into())).await.unwrap();
    assert!(addresses.iter().any(IpAddr::is_loopback));
}

#[test]
fn targets_handle_ipv4_ipv6_and_bounded_cidr_without_urls() {
    let Target::Addresses(addresses) = parse_target("192.0.2.99/30").unwrap() else {
        panic!()
    };
    assert_eq!(
        addresses,
        vec![
            "192.0.2.97".parse::<IpAddr>().unwrap(),
            "192.0.2.98".parse().unwrap()
        ]
    );
    let Target::Addresses(addresses) = parse_target("2001:db8::/126").unwrap() else {
        panic!()
    };
    assert_eq!(addresses.len(), 4);
    let Target::Addresses(addresses) = parse_target("192.0.2.1/31").unwrap() else {
        panic!()
    };
    assert_eq!(addresses.len(), 2);
    assert!(matches!(parse_target("[::1]"), Ok(Target::Addresses(_))));
    assert!(matches!(
        parse_target("example.test."),
        Ok(Target::Hostname(_))
    ));
    for target in [
        "",
        "https://example.test",
        "10.0.0.1:80",
        "192.0.2.0/16",
        "2001:db8::/64",
        "::/129",
        "fe80::1%wlan0",
        "a..test",
        "-host.test",
        "host;exit",
    ] {
        assert!(parse_target(target).is_err(), "{target}");
    }
    assert!(check_budget(256, 65535).is_err());
    assert!(check_budget(1, 65535).is_ok());
}

#[tokio::test]
async fn scans_real_open_and_closed_local_ports_and_roundtrips_report() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scanner = Scanner::default();
    scanner.start(request(port)).unwrap();
    let first = done(&scanner).await;
    assert_eq!(first.phase, Phase::Completed);
    assert_eq!((first.completed, first.open, first.closed), (1, 1, 0));
    assert_eq!(first.results[0].port, port);
    assert_ne!(first.results[0].evidence, "response");
    let report: ScanSnapshot =
        serde_json::from_str(&serde_json::to_string_pretty(&first).unwrap()).unwrap();
    assert_eq!(report.id, first.id);
    assert_eq!(
        report.results[0].address,
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(scanner.snapshot(0).unwrap().results.len(), 0);
    assert!(scanner
        .start(ScanRequest {
            ports: "0".into(),
            ..request(port)
        })
        .is_err());
    assert_eq!(scanner.snapshot(1).unwrap().id, first.id);
    drop(listener);
    scanner.start(request(port)).unwrap();
    let closed = done(&scanner).await;
    assert_eq!((closed.completed, closed.open, closed.closed), (1, 0, 1));
    assert!(closed.results.is_empty());
}

#[tokio::test]
async fn detects_ssh_from_real_server_banner_on_an_arbitrary_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"SS").await.unwrap();
        tokio::task::yield_now().await;
        socket.write_all(b"H-2.0-OpenSSH_test\r\n").await.unwrap();
    });
    let scanner = Scanner::default();
    scanner
        .start(ScanRequest {
            service_detection: true,
            ..request(port)
        })
        .unwrap();
    let result = done(&scanner).await;
    assert_eq!(result.results[0].service, "ssh");
    assert_eq!(result.results[0].evidence, "response");
    assert_eq!(result.results[0].product, "OpenSSH_test");
    server.await.unwrap();
}

#[tokio::test]
async fn reads_split_http_headers_and_records_actual_server_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 512];
        let count = socket.read(&mut request).await.unwrap();
        assert!(request[..count].starts_with(b"HEAD / HTTP/1.1\r\n"));
        socket.write_all(b"HTTP/1.1 200 OK\r\nSer").await.unwrap();
        tokio::task::yield_now().await;
        socket
            .write_all(b"ver: local-fixture/1.0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let result = probe::http(&mut stream, "localhost").await.unwrap();
    assert_eq!(result.service, "http");
    assert_eq!(result.product, "local-fixture/1.0");
    server.await.unwrap();
}

#[tokio::test]
async fn cancellation_joins_workers_closes_sockets_and_allows_restart() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scanner = Scanner::default();
    scanner
        .start(ScanRequest {
            service_detection: true,
            probe_timeout_ms: 5000,
            ..request(port)
        })
        .unwrap();
    let (mut socket, _) = listener.accept().await.unwrap();
    assert!(scanner.start(request(port)).is_err());
    assert_eq!(scanner.stop().unwrap().phase, Phase::Cancelling);
    let cancelled = done(&scanner).await;
    assert_eq!(cancelled.phase, Phase::Cancelled);
    let mut byte = [0; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    scanner.start(request(port)).unwrap();
    assert_eq!(done(&scanner).await.phase, Phase::Completed);
}

#[tokio::test]
async fn silent_open_service_stays_open_without_fabricated_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scanner = Scanner::default();
    scanner
        .start(ScanRequest {
            service_detection: true,
            probe_timeout_ms: 100,
            ..request(port)
        })
        .unwrap();
    let (_socket, _) = listener.accept().await.unwrap();
    let data = done(&scanner).await;
    assert_eq!(data.open, 1);
    assert_ne!(data.results[0].evidence, "response");
    assert!(data.results[0].banner.is_empty());
}

#[tokio::test]
async fn concurrency_is_bounded_while_slow_probes_are_active() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let scanner = Scanner::default();
    // The first host's pending probe must prevent a second connection attempt.
    scanner
        .start(ScanRequest {
            target: "127.0.0.0/30".into(),
            concurrency: 1,
            service_detection: true,
            probe_timeout_ms: 5000,
            ..request(port)
        })
        .unwrap();
    let (_socket, _) = listener.accept().await.unwrap();
    assert!(timeout(Duration::from_millis(80), listener.accept())
        .await
        .is_err());
    assert_eq!(scanner.snapshot(1).unwrap().completed, 0);
    scanner.stop().unwrap();
    assert_eq!(done(&scanner).await.phase, Phase::Cancelled);
}
