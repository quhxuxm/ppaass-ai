use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static VPN_DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static VPN_UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static DNS_RECORDS: OnceLock<ArcSwap<Vec<DnsResolutionRecord>>> = OnceLock::new();
const DNS_RECORD_CAPACITY: usize = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolutionRecord {
    pub timestamp_ms: u128,
    #[serde(default = "agent_dns_resolver")]
    pub resolver: String,
    pub client: String,
    pub upstream: String,
    pub query: String,
    pub record_type: String,
    pub status: String,
    pub answers: Vec<String>,
    pub duration_ms: u128,
}

fn agent_dns_resolver() -> String {
    "agent".to_string()
}

pub fn record_download(bytes: usize) {
    VPN_DOWNLOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn record_upload(bytes: usize) {
    VPN_UPLOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn download_bytes() -> u64 {
    VPN_DOWNLOAD_BYTES.load(Ordering::Relaxed)
}

pub fn upload_bytes() -> u64 {
    VPN_UPLOAD_BYTES.load(Ordering::Relaxed)
}

pub fn record_dns_resolution(record: DnsResolutionRecord) {
    let records = dns_records();
    loop {
        let current = records.load_full();
        let drop_count = current
            .len()
            .saturating_add(1)
            .saturating_sub(DNS_RECORD_CAPACITY);
        let mut next = Vec::with_capacity(current.len().saturating_add(1) - drop_count);
        next.extend(current.iter().skip(drop_count).cloned());
        next.push(record.clone());
        let previous = records.compare_and_swap(&current, Arc::new(next));
        if Arc::ptr_eq(&*previous, &current) {
            return;
        }
    }
}

pub fn dns_resolution_records_json() -> String {
    serde_json::to_string(dns_records().load_full().as_ref()).unwrap_or_else(|_| "[]".to_string())
}

fn dns_records() -> &'static ArcSwap<Vec<DnsResolutionRecord>> {
    DNS_RECORDS.get_or_init(|| ArcSwap::from_pointee(Vec::with_capacity(DNS_RECORD_CAPACITY)))
}

pub fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
