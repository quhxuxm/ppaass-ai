use anyhow::{Context, Result};
use std::net::IpAddr;

pub async fn verify_tun_route(
    target_host: &str,
    target_port: u16,
    expected_interface: Option<&str>,
) -> Result<String> {
    let target_ip = tokio::net::lookup_host((target_host, target_port))
        .await
        .with_context(|| format!("无法解析 TUN 测试目标 {target_host}"))?
        .map(|address| address.ip())
        .next()
        .context("TUN 测试目标没有可用 IP")?;
    let route = route_output(target_ip)?;
    let interface = parse_route_interface(&route).context("无法从系统路由结果识别出口网卡")?;
    if let Some(expected) = expected_interface {
        anyhow::ensure!(
            interface == expected,
            "目标实际走 {interface}，未走指定的 TUN 网卡 {expected}"
        );
    } else {
        let normalized = interface.to_ascii_lowercase();
        anyhow::ensure!(
            normalized.starts_with("tun") || normalized.starts_with("utun"),
            "目标实际走 {interface}，没有经过 TUN；拒绝记录伪 TUN 成绩"
        );
    }
    Ok(interface)
}

pub fn parse_route_interface(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("interface:") {
            return nonempty(value);
        }
        let fields = trimmed.split_whitespace().collect::<Vec<_>>();
        if let Some(position) = fields.iter().position(|field| *field == "dev")
            && let Some(value) = fields.get(position + 1)
        {
            return nonempty(value);
        }
    }
    None
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(target_os = "macos")]
fn route_output(target: IpAddr) -> Result<String> {
    command_output("route", &["-n", "get", &target.to_string()])
}

#[cfg(target_os = "linux")]
fn route_output(target: IpAddr) -> Result<String> {
    command_output("ip", &["route", "get", &target.to_string()])
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_output(_target: IpAddr) -> Result<String> {
    anyhow::bail!("当前平台暂不支持自动校验 TUN 路由")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_output(program: &str, args: &[&str]) -> Result<String> {
    use std::process::Command;

    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("无法运行系统路由命令 {program}"))?;
    anyhow::ensure!(
        output.status.success(),
        "系统路由命令失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
