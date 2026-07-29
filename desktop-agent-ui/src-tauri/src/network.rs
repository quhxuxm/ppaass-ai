use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::models::ConnectivityCheck;
use crate::process_util::hide_child_console;

mod tun_probe;

use tun_probe::{resolved_tun_name, tun_interface_ready, tun_routes_ready};

const QUIC_PROBE_SIZE: usize = 1200;
const QUIC_RESERVED_VERSION: u32 = 0x0a0a0a0a;
const QUIC_PROBE_ATTEMPTS: usize = 3;

pub(crate) fn probe_tun_ready(tun_name: &str) -> (bool, String) {
    let interface_ready = tun_interface_ready(tun_name);
    let routes_ready = tun_routes_ready(tun_name);
    let display_name = resolved_tun_name(tun_name).unwrap_or_else(|| tun_name.to_string());

    match (interface_ready, routes_ready) {
        (true, true) => (true, format!("TUN 已就绪：{display_name}")),
        (false, true) => (false, format!("TUN 网卡未就绪：{display_name}")),
        (true, false) => (false, format!("TUN 路由未就绪：{display_name}")),
        (false, false) => (false, format!("TUN 网卡和路由未就绪：{display_name}")),
    }
}

pub(crate) fn failed_connectivity_check(
    target: &str,
    protocol: &str,
    url: &str,
    route_label: &str,
    error: &str,
) -> ConnectivityCheck {
    ConnectivityCheck {
        target: target.to_string(),
        protocol: protocol.to_string(),
        url: url.to_string(),
        proxy_url: route_label.to_string(),
        success: false,
        http_code: None,
        duration_ms: 0,
        error: Some(error.to_string()),
    }
}

pub(crate) fn run_curl_check(
    target: &str,
    protocol: &str,
    url: &str,
    proxy_url: Option<&str>,
    route_label: &str,
) -> ConnectivityCheck {
    let start = Instant::now();
    let null_output = if cfg!(target_os = "windows") {
        "NUL"
    } else {
        "/dev/null"
    };
    let curl_bin = if cfg!(target_os = "windows") {
        "curl.exe"
    } else {
        "curl"
    };

    let mut args = vec![
        "-sS".to_string(),
        "-L".to_string(),
        "-o".to_string(),
        null_output.to_string(),
        "-w".to_string(),
        "http_code=%{http_code}\ntime_total=%{time_total}\nerrormsg=%{errormsg}\n".to_string(),
    ];
    if let Some(proxy_url) = proxy_url {
        args.extend(["--proxy".to_string(), proxy_url.to_string()]);
    } else {
        args.extend(["--noproxy".to_string(), "*".to_string()]);
    }
    args.extend([
        "--connect-timeout".to_string(),
        "10".to_string(),
        "--max-time".to_string(),
        "25".to_string(),
        url.to_string(),
    ]);

    let mut command = Command::new(curl_bin);
    command.args(&args);
    hide_child_console(&mut command);
    let output = command.output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let http_code = parse_http_code(&stdout);
            let errormsg = curl_field(&stdout, "errormsg")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| stderr.trim().to_string());
            let success =
                output.status.success() && http_code.is_some_and(|code| (200..400).contains(&code));

            ConnectivityCheck {
                target: target.to_string(),
                protocol: protocol.to_string(),
                url: url.to_string(),
                proxy_url: route_label.to_string(),
                success,
                http_code,
                duration_ms: start.elapsed().as_millis(),
                error: if success {
                    None
                } else if errormsg.is_empty() {
                    Some(format!("curl exit status: {}", output.status))
                } else {
                    Some(errormsg)
                },
            }
        }
        Err(err) => ConnectivityCheck {
            target: target.to_string(),
            protocol: protocol.to_string(),
            url: url.to_string(),
            proxy_url: route_label.to_string(),
            success: false,
            http_code: None,
            duration_ms: start.elapsed().as_millis(),
            error: Some(format!("运行 curl 失败：{err}")),
        },
    }
}

pub(crate) fn run_quic_check(
    target: &str,
    host: &str,
    route_label: &str,
    attempt_timeout: Duration,
) -> ConnectivityCheck {
    let start = Instant::now();
    let url = format!("quic://{host}:443");
    let result = run_quic_version_negotiation(host, attempt_timeout);

    match result {
        Ok(detail) => ConnectivityCheck {
            target: target.to_string(),
            protocol: "QUIC".to_string(),
            url,
            proxy_url: route_label.to_string(),
            success: true,
            http_code: None,
            duration_ms: start.elapsed().as_millis(),
            error: Some(detail),
        },
        Err(err) => ConnectivityCheck {
            target: target.to_string(),
            protocol: "QUIC".to_string(),
            url,
            proxy_url: route_label.to_string(),
            success: false,
            http_code: None,
            duration_ms: start.elapsed().as_millis(),
            error: Some(err),
        },
    }
}

pub(crate) fn proxy_url(scheme: &str, listen_addr: &str) -> String {
    if let Ok(addr) = listen_addr.parse::<SocketAddr>() {
        return format!("{scheme}://{}", display_connect_addr(addr));
    }
    format!("{scheme}://{listen_addr}")
}

pub(crate) fn connect_addr(listen_addr: &str) -> Option<SocketAddr> {
    if let Ok(addr) = listen_addr.parse::<SocketAddr>() {
        return Some(normalize_listen_addr(addr));
    }
    let mut addrs = listen_addr.to_socket_addrs().ok()?;
    addrs.next().map(normalize_listen_addr)
}

fn curl_field(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line.strip_prefix(key)?;
        value.strip_prefix('=').map(ToOwned::to_owned)
    })
}

fn parse_http_code(output: &str) -> Option<u16> {
    let value = curl_field(output, "http_code")?;
    let code = value.parse::<u16>().ok()?;
    (code > 0).then_some(code)
}

fn normalize_listen_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

fn display_connect_addr(addr: SocketAddr) -> String {
    let addr = normalize_listen_addr(addr);
    match addr.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
    }
}

fn run_quic_version_negotiation(host: &str, attempt_timeout: Duration) -> Result<String, String> {
    let target = resolve_quic_target(host)?;
    let bind_addr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|err| format!("绑定 UDP socket 失败：{err}"))?;
    socket
        .set_read_timeout(Some(attempt_timeout))
        .map_err(|err| format!("设置 QUIC 超时失败：{err}"))?;
    socket
        .connect(target)
        .map_err(|err| format!("连接 UDP/443 失败：{err}"))?;

    let mut last_error = "UDP/443 QUIC 探测超时".to_string();
    let mut response = [0u8; 1500];
    for attempt in 1..=QUIC_PROBE_ATTEMPTS {
        // Native UDP transport is intentionally unreliable. A cold session may lose its first
        // application datagram while authentication/flow state is converging, so diagnostics
        // must behave like a real QUIC client and retry instead of treating one loss as failure.
        let probe = quic_version_negotiation_probe();
        socket
            .send(&probe)
            .map_err(|err| format!("发送 QUIC 探测包失败（第 {attempt} 次）：{err}"))?;

        match socket.recv(&mut response) {
            Ok(n) if is_quic_version_negotiation_response(&response[..n]) => {
                return Ok(format!(
                    "QUIC Version Negotiation 响应：{n} bytes，目标 {target}，第 {attempt} 次探测"
                ));
            }
            Ok(n) => {
                last_error = format!(
                    "UDP/443 有响应，但不是 QUIC Version Negotiation：{n} bytes（第 {attempt} 次）"
                );
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                last_error = format!("UDP/443 QUIC 第 {attempt} 次探测超时");
            }
            Err(err) => {
                last_error = format!("接收 QUIC 响应失败（第 {attempt} 次）：{err}");
            }
        }
    }

    Err(format!("{last_error}；共尝试 {QUIC_PROBE_ATTEMPTS} 次"))
}

fn resolve_quic_target(host: &str) -> Result<SocketAddr, String> {
    let mut fallback = None;
    for addr in (host, 443)
        .to_socket_addrs()
        .map_err(|err| format!("解析 QUIC 目标失败：{err}"))?
    {
        if fallback.is_none() {
            fallback = Some(addr);
        }
        if addr.is_ipv4() {
            return Ok(addr);
        }
    }
    fallback.ok_or_else(|| format!("解析 QUIC 目标失败：{host} 无可用地址"))
}

fn quic_version_negotiation_probe() -> [u8; QUIC_PROBE_SIZE] {
    let mut packet = [0u8; QUIC_PROBE_SIZE];
    fill_probe_payload(&mut packet);
    let dcid = connection_id(0x5eed_f00d_cafe_babe);
    let scid = connection_id(0xdec0_de01_2345_6789);

    let mut offset = 0;
    packet[offset] = 0xc0;
    offset += 1;
    packet[offset..offset + 4].copy_from_slice(&QUIC_RESERVED_VERSION.to_be_bytes());
    offset += 4;
    packet[offset] = dcid.len() as u8;
    offset += 1;
    packet[offset..offset + dcid.len()].copy_from_slice(&dcid);
    offset += dcid.len();
    packet[offset] = scid.len() as u8;
    offset += 1;
    packet[offset..offset + scid.len()].copy_from_slice(&scid);
    packet
}

fn fill_probe_payload(packet: &mut [u8]) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0xa5a5_5a5a_0123_4567);
    let mut state = nanos ^ 0x9e37_79b9_7f4a_7c15;
    for byte in packet {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *byte = state as u8;
    }
}

fn connection_id(seed: u64) -> [u8; 8] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    (seed ^ now).to_be_bytes()
}

fn is_quic_version_negotiation_response(response: &[u8]) -> bool {
    response.len() >= 7 && (response[0] & 0x80) != 0 && response[1..5] == [0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_probe_uses_reserved_version_and_minimum_size() {
        let packet = quic_version_negotiation_probe();

        assert_eq!(packet.len(), QUIC_PROBE_SIZE);
        assert_eq!(packet[0], 0xc0);
        assert_eq!(
            u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]),
            QUIC_RESERVED_VERSION
        );
        assert_eq!(packet[5], 8);
        assert_eq!(packet[14], 8);
    }

    #[test]
    fn recognizes_quic_version_negotiation_response() {
        assert!(is_quic_version_negotiation_response(&[
            0xc0, 0, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8
        ]));
        assert!(!is_quic_version_negotiation_response(&[
            0xc0, 0, 0, 0, 1, 8, 1, 2
        ]));
        assert!(!is_quic_version_negotiation_response(&[
            0x40, 0, 0, 0, 0, 8, 1
        ]));
    }
}
