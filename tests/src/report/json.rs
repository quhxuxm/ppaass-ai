use super::*;

pub(super) fn generate_json_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_udp_json_report(
    results: &UdpPerformanceTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_tcp_json_report(
    results: &TcpPerformanceTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_max_throughput_json_report(
    results: &MaxThroughputTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_quic_json_report(results: &QuicProbeTestResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_large_download_json_report(
    results: &LargeDownloadTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
