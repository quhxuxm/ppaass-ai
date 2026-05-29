//! 遥测模块：tracing 初始化（标准输出或文件）以及供协议处理器使用的
//! 流量统计辅助函数 `emit_traffic`。

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

static TOTAL_OUTBOUND_BYTES: AtomicU64 = AtomicU64::new(0);
static TOTAL_INBOUND_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TrafficSnapshot {
    pub outbound_bytes: u64,
    pub inbound_bytes: u64,
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

    TOTAL_OUTBOUND_BYTES.fetch_add(outbound_bytes, Ordering::Relaxed);
    TOTAL_INBOUND_BYTES.fetch_add(inbound_bytes, Ordering::Relaxed);

    info!(
        protocol = %protocol,
        target = %target,
        outbound_bytes,
        inbound_bytes,
        "流量统计"
    );
}

#[allow(dead_code)]
pub fn traffic_snapshot() -> TrafficSnapshot {
    TrafficSnapshot {
        outbound_bytes: TOTAL_OUTBOUND_BYTES.load(Ordering::Relaxed),
        inbound_bytes: TOTAL_INBOUND_BYTES.load(Ordering::Relaxed),
    }
}
