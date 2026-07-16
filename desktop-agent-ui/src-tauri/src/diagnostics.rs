use std::fs;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::time::timeout;

use crate::config::{locate_config_path, summarize_config};
use crate::models::{ConnectivityCheck, ConnectivityReport};
use crate::network::{
    connect_addr, failed_connectivity_check, probe_tun_ready, proxy_url, run_curl_check,
    run_quic_check,
};
use crate::process_util::current_time_millis;

pub(crate) fn run_connectivity_tests_blocking(
    path: Option<String>,
) -> Result<ConnectivityReport, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let listen_addr = summary.listen_addr.clone();
    let tun_enabled = summary.tun_enabled;
    let tun_name = summary.tun_name.clone();
    let agent_reachable = connect_addr(&listen_addr)
        .map(|addr| tcp_connect_timeout(addr, Duration::from_millis(900)))
        .unwrap_or(false);

    let targets = [
        (
            "Google",
            "https://www.google.com/generate_204",
            "www.google.com",
        ),
        (
            "YouTube",
            "https://www.youtube.com/generate_204",
            "www.youtube.com",
        ),
    ];
    let protocols = [
        ("HTTP", proxy_url("http", &listen_addr)),
        ("SOCKS5", proxy_url("socks5h", &listen_addr)),
    ];

    let mut result_jobs = Vec::new();
    for &(target, url, _) in &targets {
        for (protocol, proxy) in &protocols {
            let target = target.to_string();
            let protocol = (*protocol).to_string();
            let url = url.to_string();
            let proxy = proxy.clone();
            result_jobs.push(thread::spawn(move || {
                run_curl_check(&target, &protocol, &url, Some(proxy.as_str()), &proxy)
            }));
        }
    }
    let results = collect_connectivity_checks(result_jobs);

    let mut tun_results = Vec::new();
    let (tun_ready, tun_status) = if tun_enabled {
        probe_tun_ready(&tun_name)
    } else {
        (false, "TUN 未启用".to_string())
    };
    if tun_enabled {
        let tun_route = format!("tun://{tun_name}");
        if tun_ready {
            // Run HTTPS checks before QUIC probes. Native UDP mode has to establish and
            // authenticate its outer session on the first UDP flow; starting two 1200-byte
            // QUIC probes alongside both HTTPS checks can temporarily starve the TUN netstack
            // and make otherwise healthy TCP checks fail. Diagnostics should observe the path,
            // not create an artificial cold-start burst on it.
            for &(target, url, _) in &targets {
                tun_results.push(run_curl_check(target, "TUN", url, None, &tun_route));
            }
            for &(target, _, quic_host) in &targets {
                tun_results.push(run_quic_check(target, quic_host, &tun_route));
            }
        } else {
            for (target, url, quic_host) in targets.iter().copied() {
                tun_results.push(failed_connectivity_check(
                    target,
                    "TUN",
                    url,
                    &tun_route,
                    &tun_status,
                ));
                tun_results.push(failed_connectivity_check(
                    target,
                    "QUIC",
                    &format!("quic://{quic_host}:443"),
                    &tun_route,
                    &tun_status,
                ));
            }
        }
    }

    Ok(ConnectivityReport {
        listen_addr,
        tun_enabled,
        tun_name,
        tun_ready,
        tun_status,
        agent_reachable,
        generated_at_ms: current_time_millis(),
        results,
        tun_results,
    })
}

fn collect_connectivity_checks(jobs: Vec<JoinHandle<ConnectivityCheck>>) -> Vec<ConnectivityCheck> {
    jobs.into_iter().filter_map(|job| job.join().ok()).collect()
}

fn tcp_connect_timeout(addr: std::net::SocketAddr, duration: Duration) -> bool {
    let Ok(runtime) = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        return false;
    };
    runtime
        .block_on(async { matches!(timeout(duration, TcpStream::connect(addr)).await, Ok(Ok(_))) })
}
