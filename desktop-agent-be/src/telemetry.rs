//! 遥测模块：tracing 初始化（标准输出或文件）以及供协议处理器使用的
//! 流量统计辅助函数 `emit_traffic`。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

static TOTAL_OUTBOUND_BYTES: AtomicU64 = AtomicU64::new(0);
static TOTAL_INBOUND_BYTES: AtomicU64 = AtomicU64::new(0);
static DNS_RECORDS: OnceLock<Mutex<VecDeque<DnsResolutionRecord>>> = OnceLock::new();
const DNS_RECORD_CAPACITY: usize = 80;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TrafficSnapshot {
    pub outbound_bytes: u64,
    pub inbound_bytes: u64,
}

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

/// 初始化全局 tracing。
/// 若 `log_dir` 不为空，日志只会按天滚动写入该目录下的文件。
/// 开启文件日志时，返回的 guard 必须在程序整个生命周期内保持存活。
pub fn init_tracing(log_dir: Option<&str>, log_file: &str, log_level: &str) -> Option<WorkerGuard> {
    let filter = EnvFilter::new(log_level);

    if let Some(log_dir) = log_dir {
        // 文件日志使用 non_blocking writer，guard 必须存活以 flush 后台缓冲。
        let file_appender = tracing_appender::rolling::daily(log_dir, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer()
            .with_writer(non_blocking)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();
        Some(guard)
    } else {
        // 未配置日志目录时只初始化 stdout layer。
        let stdout_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true);
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
        None
    }
}

/// 以 INFO 级别记录一条流量统计日志。
/// 原 TUI 版本通过结构化 channel 渲染这些数据；无界面版本直接写日志，数据仍可观测。
pub fn emit_traffic<S1: Into<String>, S2: Into<String>>(
    protocol: S1,
    target: S2,
    outbound_bytes: u64,
    inbound_bytes: u64,
) {
    let protocol = protocol.into();
    let target = target.into();

    record_traffic(outbound_bytes, inbound_bytes);

    info!(
        protocol = %protocol,
        target = %target,
        outbound_bytes,
        inbound_bytes,
        "流量统计"
    );
}

/// 只累计流量快照，不输出逐包日志。
///
/// UDP/QUIC 中继可能是高包率路径，如果每个 datagram 都调用 `emit_traffic` 会把日志
/// 系统打满；总览页只需要累计值和采样差分，因此这里提供无日志的热路径入口。
pub fn record_traffic(outbound_bytes: u64, inbound_bytes: u64) {
    TOTAL_OUTBOUND_BYTES.fetch_add(outbound_bytes, Ordering::Relaxed);
    TOTAL_INBOUND_BYTES.fetch_add(inbound_bytes, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn traffic_snapshot() -> TrafficSnapshot {
    TrafficSnapshot {
        outbound_bytes: TOTAL_OUTBOUND_BYTES.load(Ordering::Relaxed),
        inbound_bytes: TOTAL_INBOUND_BYTES.load(Ordering::Relaxed),
    }
}

pub fn emit_dns_resolution(record: DnsResolutionRecord) {
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

#[allow(dead_code)]
pub fn dns_resolution_records() -> Vec<DnsResolutionRecord> {
    DNS_RECORDS
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(DNS_RECORD_CAPACITY)))
        .lock()
        .map(|records| records.iter().cloned().collect())
        .unwrap_or_default()
}

pub fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
