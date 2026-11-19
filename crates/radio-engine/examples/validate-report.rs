//! Offline contract checker for reports produced by an external Linux sensor.
use radio_engine::{parse_report, MAX_REPORT_BYTES};
use std::io::Read;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("Usage: validate-report <report.json>")?;
    if args.next().is_some() {
        return Err("Usage: validate-report <report.json>".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take((MAX_REPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let report = parse_report(&bytes)?;
    println!(
        "Accepted schema v{} report: {} observed transmitter addresses. Offline metadata only.",
        report.schema_version,
        report.observations.len()
    );
    Ok(())
}
