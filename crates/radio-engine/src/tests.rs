use super::*;
use serde_json::{json, Value};

fn report() -> Value {
    json!({
        "schemaVersion": 1,
        "source": "external-wifi-sensor",
        "sensor": {"id":"linux-1","label":"Linux sensor","adapter":"wlan1","driver":"ath9k_htc","bands":["2.4GHz"],"channels":[6]},
        "startedAt": 1_700_000_000_000u64,
        "endedAt": 1_700_000_001_000u64,
        "observations": [{"transmitter":"02:AA:22:33:44:55","firstSeen":1_700_000_000_100u64,"lastSeen":1_700_000_000_900u64,"frames":3,"rssiDbm":-55.5,"channel":6,"frequencyMhz":2437,"frameTypes":["probe-request"]}]
    })
}

fn parse(value: &Value) -> Result<WifiSensorReport, String> {
    parse_report(&serde_json::to_vec(value).unwrap())
}

#[test]
fn valid_report_round_trips_without_claiming_live_support() {
    let mut store = WifiSensorStore::default();
    let status = store
        .import(&serde_json::to_vec(&report()).unwrap())
        .unwrap();
    assert_eq!(status.schema_version, 1);
    assert_eq!(status.transport, "report-import");
    assert!(!status.live_supported);
    assert!(status.last_error.is_none());
    let report = status.report.unwrap();
    assert_eq!(report.observations[0].transmitter, "02:aa:22:33:44:55");
    assert_eq!(parse_report(&store.export().unwrap()).unwrap(), report);
    assert!(store.clear().report.is_none());
    assert!(store.export().is_err());
}

#[test]
fn failed_import_preserves_the_previous_report() {
    let mut store = WifiSensorStore::default();
    let previous = store
        .import(&serde_json::to_vec(&report()).unwrap())
        .unwrap();
    let mut invalid = report();
    invalid["observations"][0]["frequencyMhz"] = json!(2412);
    assert!(store
        .import(&serde_json::to_vec(&invalid).unwrap())
        .is_err());
    assert_eq!(store.status(), previous);
    assert!(store.import(b"{truncated").is_err());
    assert_eq!(store.status(), previous);
}

#[test]
fn unsupported_versions_sources_and_unknown_fields_are_rejected() {
    for (field, value) in [
        ("schemaVersion", json!(2)),
        ("source", json!("android-live")),
        ("physicalPhones", json!(123)),
    ] {
        let mut input = report();
        input[field] = value;
        assert!(parse(&input).is_err(), "field {field}");
    }
    let mut input = report();
    input["observations"][0]["ssid"] = json!("not-in-v1");
    assert!(parse(&input).is_err());
}

#[test]
fn oversized_or_invalid_json_is_rejected_before_use() {
    assert!(parse_report(&vec![b' '; MAX_REPORT_BYTES + 1]).is_err());
    assert!(parse_report(b"\xff").is_err());
    assert!(parse_report(b"null").is_err());
    let mut input = report();
    input["observations"] =
        Value::Array(vec![input["observations"][0].clone(); MAX_OBSERVATIONS + 1]);
    assert!(parse(&input).unwrap_err().contains("2,048"));
}

#[test]
fn timestamps_are_bounded_ordered_and_within_report_interval() {
    for (field, value) in [
        ("firstSeen", json!(1_699_999_999_999u64)),
        ("lastSeen", json!(1_700_000_001_001u64)),
        ("firstSeen", json!(1_700_000_000_999u64)),
        ("lastSeen", json!(-1)),
        ("lastSeen", json!(1.5)),
        ("lastSeen", json!(MAX_TIMESTAMP_MS + 1)),
    ] {
        let mut input = report();
        input["observations"][0][field] = value;
        assert!(parse(&input).is_err(), "field {field}");
    }
    let mut input = report();
    input["endedAt"] = json!(MAX_TIMESTAMP_MS + 1);
    assert!(parse(&input).is_err());
    input["endedAt"] = json!(0);
    assert!(parse(&input).is_err());
}

#[test]
fn transmitter_addresses_are_unique_unicast_and_not_device_identifiers() {
    for mac in [
        "ff:ff:ff:ff:ff:ff",
        "01:11:22:33:44:55",
        "00:00:00:00:00:00",
        "aa-bb-cc-dd-ee-ff",
        "02:11:22:33:44:5x",
    ] {
        let mut input = report();
        input["observations"][0]["transmitter"] = json!(mac);
        assert!(parse(&input).is_err(), "{mac}");
    }
    let mut input = report();
    let mut duplicate = input["observations"][0].clone();
    duplicate["transmitter"] = json!("02:aa:22:33:44:55");
    input["observations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(parse(&input).unwrap_err().contains("only once"));
}

#[test]
fn supported_bands_include_channel_14_and_special_6ghz_channel_2() {
    for (band, channel, frequency) in [
        ("2.4GHz", 14, 2484),
        ("5GHz", 36, 5180),
        ("5GHz", 177, 5885),
        ("6GHz", 1, 5955),
        ("6GHz", 2, 5935),
        ("6GHz", 233, 7115),
    ] {
        let mut input = report();
        input["sensor"]["bands"] = json!([band]);
        input["sensor"]["channels"] = json!([channel]);
        input["observations"][0]["channel"] = json!(channel);
        input["observations"][0]["frequencyMhz"] = json!(frequency);
        assert!(parse(&input).is_ok(), "{band} channel {channel}");
    }
}

#[test]
fn inconsistent_radio_metadata_is_rejected() {
    for (channel, frequency) in [
        (0, 2437),
        (6, 2412),
        (14, 2477),
        (234, 7120),
        (u32::MAX, u32::MAX),
    ] {
        let mut input = report();
        input["observations"][0]["channel"] = json!(channel);
        input["observations"][0]["frequencyMhz"] = json!(frequency);
        assert!(parse(&input).is_err());
    }
    let mut input = report();
    input["sensor"]["bands"] = json!(["5GHz"]);
    input["sensor"]["channels"] = json!([36]);
    assert!(parse(&input).is_err());
    input["sensor"]["bands"] = json!(["2.4GHz"]);
    input["sensor"]["channels"] = json!([1]);
    assert!(parse(&input).is_err());
}

#[test]
fn bounded_lists_and_untrusted_text_are_validated() {
    for (field, value) in [
        ("id", json!("\nspoof")),
        ("label", json!("")),
        ("driver", json!("x".repeat(129))),
        ("bands", json!(["2.4GHz", "2.4GHz"])),
        ("bands", json!(["unknown"])),
        ("channels", json!([6, 6])),
        ("channels", json!([])),
    ] {
        let mut input = report();
        input["sensor"][field] = value;
        assert!(parse(&input).is_err(), "{field}");
    }
    for value in [
        json!([]),
        json!(["data", "data"]),
        json!(["\u{0000}"]),
        json!(["a".repeat(49)]),
        json!((0..33).map(|n| format!("type-{n}")).collect::<Vec<_>>()),
    ] {
        let mut input = report();
        input["observations"][0]["frameTypes"] = value;
        assert!(parse(&input).is_err());
    }
}

#[test]
fn rssi_and_frame_counts_require_observed_values() {
    let mut input = report();
    input["observations"][0]["rssiDbm"] = Value::Null;
    assert!(parse(&input).is_ok());
    for rssi in [-128.0, 21.0] {
        input["observations"][0]["rssiDbm"] = json!(rssi);
        assert!(parse(&input).is_err());
    }
    input["observations"][0]["rssiDbm"] = json!(-55);
    input["observations"][0]["frames"] = json!(0);
    assert!(parse(&input).is_err());
    let wire = serde_json::to_string(&report())
        .unwrap()
        .replace("-55.5", "1e400");
    assert!(parse_report(wire.as_bytes()).is_err());
}

#[test]
fn frame_counts_remain_exact_when_delivered_as_javascript_numbers() {
    let mut input = report();
    input["observations"][0]["frames"] = json!(MAX_FRAME_COUNT);
    let accepted = parse(&input).unwrap();
    assert_eq!(accepted.observations[0].frames, MAX_FRAME_COUNT);
    let exported = serde_json::to_vec(&accepted).unwrap();
    assert_eq!(
        parse_report(&exported).unwrap().observations[0].frames,
        MAX_FRAME_COUNT
    );
    for frames in [MAX_FRAME_COUNT + 1, u64::MAX] {
        input["observations"][0]["frames"] = json!(frames);
        assert!(parse(&input).unwrap_err().contains("Frame count"));
    }
}

#[test]
fn maximum_observation_count_remains_round_trippable() {
    let mut input = report();
    let template = input["observations"][0].clone();
    input["observations"] = Value::Array(
        (0..MAX_OBSERVATIONS)
            .map(|n| {
                let mut observation = template.clone();
                observation["transmitter"] =
                    json!(format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256));
                observation
            })
            .collect(),
    );
    let mut store = WifiSensorStore::default();
    assert_eq!(
        store
            .import(&serde_json::to_vec(&input).unwrap())
            .unwrap()
            .report
            .unwrap()
            .observations
            .len(),
        MAX_OBSERVATIONS
    );
    let exported = store.export().unwrap();
    assert!(exported.len() <= MAX_REPORT_BYTES);
    assert_eq!(
        parse_report(&exported).unwrap().observations.len(),
        MAX_OBSERVATIONS
    );
}
