use std::fs;
use std::net::TcpStream as StdTcpStream;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::config::{locate_config_path, summarize_config};
use crate::models::{ConnectivityCheck, ConnectivityReport};
use crate::network::{
    connect_addr, failed_connectivity_check, probe_tun_ready, proxy_url, run_curl_check,
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
        .map(|addr| StdTcpStream::connect_timeout(&addr, Duration::from_millis(900)).is_ok())
        .unwrap_or(false);

    let targets = [
        ("Google", "https://www.google.com/generate_204"),
        ("YouTube", "https://www.youtube.com/generate_204"),
    ];
    let protocols = [
        ("HTTP", proxy_url("http", &listen_addr)),
        ("SOCKS5", proxy_url("socks5h", &listen_addr)),
    ];

    let mut result_jobs = Vec::new();
    for &(target, url) in &targets {
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
            let mut tun_jobs = Vec::new();
            for &(target, url) in &targets {
                let target = target.to_string();
                let url = url.to_string();
                let tun_route = tun_route.clone();
                tun_jobs.push(thread::spawn(move || {
                    run_curl_check(&target, "TUN", &url, None, &tun_route)
                }));
            }
            tun_results = collect_connectivity_checks(tun_jobs);
        } else {
            for (target, url) in targets.iter().copied() {
                tun_results.push(failed_connectivity_check(
                    target,
                    "TUN",
                    url,
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
