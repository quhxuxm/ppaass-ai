use std::time::Instant;

use common::AuthenticatedConnection;
use protocol::DEFAULT_SPEED_TEST_DOWNLOAD_BYTES;
use serde::Serialize;

use crate::config::AndroidAgentConfig;

#[derive(Serialize)]
struct SpeedTestResult {
    latency_ms: u64,
    download_bytes: u64,
    download_millis: u64,
    bytes_per_second: u64,
}

#[derive(Serialize)]
struct SpeedTestError<'a> {
    error: &'a str,
}

pub fn run_json(config_json: &str) -> String {
    match run(config_json) {
        Ok(result) => serde_json::to_string(&result),
        Err(error) => serde_json::to_string(&SpeedTestError { error: &error }),
    }
    .unwrap_or_else(|_| "{\"error\":\"测速结果序列化失败\"}".to_string())
}

fn run(config_json: &str) -> Result<SpeedTestResult, String> {
    let config: AndroidAgentConfig =
        serde_json::from_str(config_json).map_err(|_| "测速配置无效".to_string())?;
    config.validate().map_err(|error| error.to_string())?;
    if config.proxy_addrs.len() != 1 {
        return Err("测速必须指定一个 Proxy Entry".to_string());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("无法启动测速任务：{error}"))?;
    runtime.block_on(measure(config))
}

async fn measure(config: AndroidAgentConfig) -> Result<SpeedTestResult, String> {
    let connect_started = Instant::now();
    let connection = AuthenticatedConnection::connect(&config)
        .await
        .map_err(|error| format!("连接 Proxy Entry 失败：{error}"))?;
    let latency_ms = elapsed_millis(connect_started);

    let download_started = Instant::now();
    let download_bytes = connection
        .download_speed_test(DEFAULT_SPEED_TEST_DOWNLOAD_BYTES)
        .await
        .map_err(|error| format!("Proxy Entry 测速失败：{error}"))?;
    let download_micros = download_started.elapsed().as_micros().max(1);
    let bytes_per_second =
        (u128::from(download_bytes) * 1_000_000 / download_micros).min(u128::from(u64::MAX)) as u64;

    Ok(SpeedTestResult {
        latency_ms,
        download_bytes,
        download_millis: (download_micros / 1_000).max(1) as u64,
        bytes_per_second,
    })
}

fn elapsed_millis(started: Instant) -> u64 {
    started
        .elapsed()
        .as_millis()
        .max(1)
        .min(u128::from(u64::MAX)) as u64
}
