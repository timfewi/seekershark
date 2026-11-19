//! Rootless TCP connect scanning. No subprocesses, raw sockets, or Nmap databases.
mod probe;

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::watch, task::JoinSet, time::timeout};

pub const MAX_HOSTS: usize = 256;
pub const MAX_RESULTS: usize = 4096;
pub const MAX_ATTEMPTS: usize = 1_048_576;
pub const COMMON_PORTS: &str = "21,22,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,1883,2049,2375,3000,3306,3389,5432,5672,5900,6379,8000,8080,8443,8888,9090,9200,11211,27017";
const MAX_DURATION: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanRequest {
    pub target: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub service_detection: bool,
    pub probe_timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    #[default]
    Idle,
    Resolving,
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}
impl Phase {
    pub fn active(self) -> bool {
        matches!(self, Self::Resolving | Self::Running | Self::Cancelling)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub address: IpAddr,
    pub port: u16,
    pub connect_ms: f64,
    pub service: String,
    pub evidence: String,
    pub port_hint: Option<String>,
    pub product: String,
    pub banner: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub id: u64,
    pub phase: Phase,
    pub request: Option<ScanRequest>,
    pub addresses: Vec<IpAddr>,
    pub port_count: usize,
    pub total: usize,
    pub completed: usize,
    pub open: usize,
    pub closed: usize,
    pub timed_out: usize,
    pub errors: usize,
    pub results_retained: usize,
    pub results_dropped: usize,
    pub results: Vec<ScanResult>,
    pub started_at: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Default)]
struct Inner {
    data: ScanSnapshot,
    results: BTreeMap<(IpAddr, u16), ScanResult>,
    cancel: Option<watch::Sender<bool>>,
    started: Option<Instant>,
}
#[derive(Clone, Default)]
pub struct Scanner(Arc<Mutex<Inner>>);

impl Scanner {
    pub fn snapshot(&self, limit: usize) -> Result<ScanSnapshot, String> {
        let inner = self.0.lock().map_err(|_| "Scan state unavailable")?;
        let mut data = inner.data.clone();
        data.results = inner
            .results
            .values()
            .take(limit.min(MAX_RESULTS))
            .cloned()
            .collect();
        if data.phase.active() {
            data.elapsed_ms = inner
                .started
                .map_or(0, |at| at.elapsed().as_millis() as u64);
        }
        Ok(data)
    }

    /// Must be called inside a Tokio runtime. Validation preserves the previous report.
    pub fn start(&self, mut request: ScanRequest) -> Result<ScanSnapshot, String> {
        request.target = request.target.trim().to_owned();
        let ports = parse_ports(&request.ports)?;
        let target = parse_target(&request.target)?;
        if !(1..=256).contains(&request.concurrency) {
            return Err("Concurrency must be between 1 and 256.".into());
        }
        if !(100..=10_000).contains(&request.timeout_ms)
            || !(100..=5_000).contains(&request.probe_timeout_ms)
        {
            return Err(
                "Connect timeout must be 100–10,000 ms; probe timeout must be 100–5,000 ms.".into(),
            );
        }
        if let Target::Addresses(addresses) = &target {
            check_budget(addresses.len(), ports.len())?;
        }
        let (cancel, receiver) = watch::channel(false);
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "Scanner requires an async runtime.")?;
        let initial = {
            let mut inner = self.0.lock().map_err(|_| "Scan state unavailable")?;
            if inner.data.phase.active() {
                return Err("A scan is already running. Stop it before starting another.".into());
            }
            inner.data = ScanSnapshot {
                id: inner.data.id.saturating_add(1),
                phase: Phase::Resolving,
                request: Some(request.clone()),
                port_count: ports.len(),
                started_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                ..Default::default()
            };
            inner.results.clear();
            inner.cancel = Some(cancel);
            inner.started = Some(Instant::now());
            inner.data.clone()
        };
        let scanner = self.clone();
        runtime.spawn(async move { scanner.run(request, target, ports, receiver).await });
        Ok(initial)
    }

    pub fn stop(&self) -> Result<ScanSnapshot, String> {
        {
            let mut inner = self.0.lock().map_err(|_| "Scan state unavailable")?;
            if inner.data.phase.active() {
                inner.data.phase = Phase::Cancelling;
                if let Some(cancel) = &inner.cancel {
                    let _ = cancel.send(true);
                }
            }
        }
        self.snapshot(150)
    }

    fn finish(&self, phase: Phase, error: Option<String>) {
        if let Ok(mut inner) = self.0.lock() {
            inner.data.phase = phase;
            inner.data.error = error;
            inner.data.elapsed_ms = inner
                .started
                .map_or(0, |at| at.elapsed().as_millis() as u64);
            inner.cancel = None;
        }
    }

    async fn run(
        &self,
        request: ScanRequest,
        target: Target,
        ports: Vec<u16>,
        mut cancel: watch::Receiver<bool>,
    ) {
        let addresses = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => { self.finish(Phase::Cancelled, None); return; }
            value = resolve(target) => match value {
                Ok(value) => value,
                Err(error) => { self.finish(Phase::Failed, Some(error)); return; }
            }
        };
        if let Err(error) = check_budget(addresses.len(), ports.len()) {
            self.finish(Phase::Failed, Some(error));
            return;
        }
        let total = addresses.len() * ports.len();
        if let Ok(mut inner) = self.0.lock() {
            inner.data.addresses = addresses.clone();
            inner.data.total = total;
            if inner.data.phase != Phase::Cancelling {
                inner.data.phase = Phase::Running;
            }
        }
        let mut tasks = JoinSet::new();
        let request = Arc::new(request);
        let mut next = 0;
        let deadline = tokio::time::sleep(MAX_DURATION);
        tokio::pin!(deadline);
        let (phase, error) = loop {
            if *cancel.borrow() {
                break (Phase::Cancelled, None);
            }
            while tasks.len() < request.concurrency && next < total {
                let address = addresses[next % addresses.len()];
                let port = ports[next / addresses.len()];
                let request = request.clone();
                tasks.spawn(async move { attempt(address, port, &request).await });
                next += 1;
            }
            if tasks.is_empty() {
                break (Phase::Completed, None);
            }
            tokio::select! {
                biased;
                _ = cancelled(&mut cancel) => break (Phase::Cancelled, None),
                _ = &mut deadline => break (Phase::Failed, Some("Scan stopped at the 15-minute time limit. Partial results are retained.".into())),
                value = tasks.join_next() => {
                    if let Some(value) = value {
                        let Ok(outcome) = value else {
                            break (Phase::Failed, Some("A scan worker stopped unexpectedly. Partial results are retained.".into()));
                        };
                        if let Ok(mut inner) = self.0.lock() {
                            inner.data.completed += 1;
                            match outcome {
                                Outcome::Open(result) => {
                                    inner.data.open += 1;
                                    if inner.results.len() < MAX_RESULTS {
                                        inner.results.insert((result.address, result.port), result);
                                        inner.data.results_retained = inner.results.len();
                                    } else { inner.data.results_dropped += 1; }
                                }
                                Outcome::Closed => inner.data.closed += 1,
                                Outcome::TimedOut => inner.data.timed_out += 1,
                                Outcome::Error => inner.data.errors += 1,
                            }
                        }
                    }
                }
            }
        };
        // Abort and join every worker before permitting another job to start.
        // Dropping the worker futures also closes their sockets.
        tasks.shutdown().await;
        self.finish(phase, error);
    }
}

async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

enum Outcome {
    Open(ScanResult),
    Closed,
    TimedOut,
    Error,
}
async fn attempt(address: IpAddr, port: u16, request: &ScanRequest) -> Outcome {
    let at = Instant::now();
    let stream = match timeout(
        Duration::from_millis(request.timeout_ms),
        TcpStream::connect(SocketAddr::new(address, port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Outcome::Closed
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::TimedOut => return Outcome::TimedOut,
        Err(_) => return Outcome::TimedOut,
        _ => return Outcome::Error,
    };
    let hint = probe::port_hint(port).map(str::to_owned);
    let mut result = ScanResult {
        address,
        port,
        connect_ms: at.elapsed().as_secs_f64() * 1000.0,
        service: hint.clone().unwrap_or_else(|| "unknown".into()),
        evidence: if hint.is_some() { "port" } else { "none" }.into(),
        port_hint: hint,
        product: String::new(),
        banner: String::new(),
    };
    if request.service_detection {
        if let Ok(Some(observed)) = timeout(
            Duration::from_millis(request.probe_timeout_ms),
            probe::detect(stream, port, &request.target),
        )
        .await
        {
            result.service = observed.service;
            result.evidence = "response".into();
            result.product = observed.product;
            result.banner = observed.banner;
        }
    }
    Outcome::Open(result)
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    if input.is_empty() || input.len() > 8192 {
        return Err(
            "Enter TCP ports such as 22,80,443 or 1-1024 (at most 8192 characters).".into(),
        );
    }
    let mut ranges = Vec::new();
    for term in input.split(',').map(str::trim) {
        let parse = |value: &str| value.trim().parse::<u16>().ok().filter(|port| *port > 0);
        if let Some((left, right)) = term.split_once('-') {
            let (Some(left), Some(right)) = (parse(left), parse(right)) else {
                return Err("Ports must be between 1 and 65535.".into());
            };
            if left > right {
                return Err("Port ranges must be in ascending order.".into());
            }
            ranges.push((left, right));
        } else {
            let port = parse(term)
                .ok_or("Ports must be between 1 and 65535, separated by commas or ranges.")?;
            ranges.push((port, port));
        }
    }
    ranges.sort_unstable();
    let mut ports: Vec<u16> = Vec::new();
    for (mut left, right) in ranges {
        if let Some(last) = ports.last() {
            if right <= *last {
                continue;
            }
            left = left.max(*last + 1);
        }
        ports.extend(left..=right);
    }
    Ok(ports)
}

enum Target {
    Addresses(Vec<IpAddr>),
    Hostname(String),
}
fn parse_target(input: &str) -> Result<Target, String> {
    let input = input.trim();
    if let Some((address, prefix)) = input.split_once('/') {
        let address: IpAddr = address
            .parse()
            .map_err(|_| "CIDR requires an IPv4 or IPv6 address, without a URL.")?;
        let prefix: u32 = prefix.parse().map_err(|_| "Invalid CIDR prefix.")?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        if prefix > bits {
            return Err("Invalid CIDR prefix.".into());
        }
        let host_bits = bits - prefix;
        if host_bits > 8 {
            return Err(
                "A CIDR scan may contain at most 256 addresses (/24 IPv4 or /120 IPv6).".into(),
            );
        }
        let count = 1_u128 << host_bits;
        let mask = !(count - 1);
        let (base, skip) = match address {
            IpAddr::V4(ip) => (u32::from(ip) as u128 & mask, host_bits >= 2),
            IpAddr::V6(ip) => (u128::from(ip) & mask, false),
        };
        let range = if skip { 1..count - 1 } else { 0..count };
        return Ok(Target::Addresses(
            range
                .map(|offset| match address {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from((base + offset) as u32)),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(base + offset)),
                })
                .collect(),
        ));
    }
    let literal = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(input);
    if let Ok(address) = literal.parse::<IpAddr>() {
        return Ok(Target::Addresses(vec![address]));
    }
    if input.is_empty()
        || input.len() > 253
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        || input.trim_end_matches('.').split('.').any(|part| {
            part.is_empty() || part.len() > 63 || part.starts_with('-') || part.ends_with('-')
        })
    {
        return Err("Enter one hostname, IPv4/IPv6 address, or CIDR. URLs, port suffixes, and IPv6 scope IDs are not supported.".into());
    }
    Ok(Target::Hostname(input.into()))
}

fn check_budget(hosts: usize, ports: usize) -> Result<(), String> {
    if hosts == 0 || hosts > MAX_HOSTS {
        return Err("A scan must resolve to 1–256 addresses.".into());
    }
    if hosts.saturating_mul(ports) > MAX_ATTEMPTS {
        return Err(
            "Scan exceeds 1,048,576 connection attempts. Reduce the target range or port range."
                .into(),
        );
    }
    Ok(())
}
async fn resolve(target: Target) -> Result<Vec<IpAddr>, String> {
    match target {
        Target::Addresses(addresses) => Ok(addresses),
        Target::Hostname(host) => {
            let values = timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 0)),
            )
            .await
            .map_err(|_| "DNS resolution timed out after 5 seconds.")?
            .map_err(|error| format!("Could not resolve target: {error}"))?;
            let addresses: BTreeSet<_> = values
                .map(|address| address.ip())
                .take(MAX_HOSTS + 1)
                .collect();
            if addresses.is_empty() || addresses.len() > MAX_HOSTS {
                return Err("Target must resolve to 1–256 addresses.".into());
            }
            Ok(addresses.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests;
