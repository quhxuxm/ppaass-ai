use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static VPN_DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static VPN_UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
static DNS_RECORDS: OnceLock<Mutex<VecDeque<DnsResolutionRecord>>> = OnceLock::new();
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
    let records =
        DNS_RECORDS.get_or_init(|| Mutex::new(VecDeque::with_capacity(DNS_RECORD_CAPACITY)));
    let Ok(mut records) = records.lock() else {
        return;
    };

    while records.len() >= DNS_RECORD_CAPACITY {
        records.pop_front();
    }
    records.push_back(record);
}

pub fn dns_resolution_records_json() -> String {
    DNS_RECORDS
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(DNS_RECORD_CAPACITY)))
        .lock()
        .map(|records| serde_json::to_string(&*records).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|_| "[]".to_string())
}

pub fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
