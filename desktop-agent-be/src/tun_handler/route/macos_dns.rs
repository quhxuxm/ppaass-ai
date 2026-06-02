use super::*;

struct MacosPfDnsGuard {
    token: Option<String>,
}

#[cfg(target_os = "macos")]
impl MacosPfDnsGuard {
    fn install(
        tun_if_index: u32,
        dns_capture_target: Ipv4Addr,
        dns_servers: &[SystemDnsServer],
        default_interfaces: &[String],
    ) -> Option<Self> {
        let tun_if_name = interface_name_for_index(Some(tun_if_index))?;
        let rules = macos_pf_dns_rules(
            &tun_if_name,
            dns_capture_target,
            dns_servers,
            default_interfaces,
        );
        if rules.trim().is_empty() {
            debug!("macOS TUN proxy_dns 未发现需要 PF 捕获的 scoped DNS");
            return None;
        }

        let token = match macos_pf_enable() {
            Ok(token) => token,
            Err(e) => {
                warn!("启用 macOS PF 以捕获 scoped DNS 失败：{e}");
                return None;
            }
        };

        let path = std::env::temp_dir().join(format!(
            "ppaass-tun-dns-pf-{}-{}.conf",
            std::process::id(),
            now_unix_secs()
        ));
        if let Err(e) = fs::write(&path, &rules) {
            warn!("写入 macOS PF DNS 规则失败：{}：{e}", path.display());
            macos_pf_release_token(token.as_deref());
            return None;
        }

        let load_result = Command::new("/sbin/pfctl")
            .args(["-a", PF_DNS_ANCHOR, "-f"])
            .arg(&path)
            .output();
        let _ = fs::remove_file(&path);

        match load_result {
            Ok(output) if output.status.success() => {
                info!("已安装 macOS scoped DNS 捕获规则（不修改系统 DNS）");
                Some(Self { token })
            }
            Ok(output) => {
                warn!(
                    "安装 macOS PF DNS 捕获规则失败：{}",
                    command_output_message(&output)
                );
                macos_pf_flush_anchor();
                macos_pf_release_token(token.as_deref());
                None
            }
            Err(e) => {
                warn!("运行 pfctl 安装 DNS 捕获规则失败：{e}");
                macos_pf_release_token(token.as_deref());
                None
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosPfDnsGuard {
    fn drop(&mut self) {
        macos_pf_flush_anchor();
        macos_pf_release_token(self.token.as_deref());
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_pf_dns_rules(
    tun_if_name: &str,
    dns_capture_target: Ipv4Addr,
    dns_servers: &[SystemDnsServer],
    default_interfaces: &[String],
) -> String {
    let mut rules = String::new();
    for server in dns_servers {
        let IpAddr::V4(dns_ip) = server.ip else {
            continue;
        };
        for interface_name in macos_dns_capture_interfaces(server, tun_if_name, default_interfaces)
        {
            rules.push_str(&format!(
                "pass out quick on {interface_name} route-to ({tun_if_name} {dns_capture_target}) inet proto {{ udp tcp }} from any to {dns_ip} port = 53 keep state\n"
            ));
        }
    }
    rules
}

#[cfg(target_os = "macos")]
fn macos_dns_capture_interfaces(
    server: &SystemDnsServer,
    tun_if_name: &str,
    default_interfaces: &[String],
) -> Vec<String> {
    let mut interfaces = Vec::new();
    if let Some(interface_name) = server.interface_name.as_deref() {
        push_macos_dns_capture_interface(&mut interfaces, interface_name, tun_if_name);
    } else {
        for interface_name in default_interfaces {
            push_macos_dns_capture_interface(&mut interfaces, interface_name, tun_if_name);
        }
    }
    interfaces
}

#[cfg(target_os = "macos")]
fn push_macos_dns_capture_interface(
    interfaces: &mut Vec<String>,
    interface_name: &str,
    tun_if_name: &str,
) {
    if interface_name == tun_if_name || interfaces.iter().any(|name| name == interface_name) {
        return;
    }
    interfaces.push(interface_name.to_string());
}

#[cfg(target_os = "macos")]
pub(super) fn macos_default_dns_interfaces(
    default_v4_if: Option<u32>,
    default_v6_if: Option<u32>,
) -> Vec<String> {
    let mut interfaces = Vec::new();
    for if_index in [default_v4_if, default_v6_if].into_iter().flatten() {
        let Some(interface_name) = interface_name_for_index(Some(if_index)) else {
            continue;
        };
        if !interfaces.iter().any(|name| name == &interface_name) {
            interfaces.push(interface_name);
        }
    }
    interfaces
}

#[cfg(target_os = "macos")]
fn macos_pf_enable() -> std::io::Result<Option<String>> {
    let output = Command::new("/sbin/pfctl").arg("-E").output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(command_output_message(&output)));
    }
    Ok(parse_pf_token(&output))
}

#[cfg(target_os = "macos")]
fn parse_pf_token(output: &std::process::Output) -> Option<String> {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    combined.lines().find_map(|line| {
        let (_, token) = line.split_once("Token")?;
        let token = token.trim_start_matches([' ', ':']).trim();
        (!token.is_empty()).then(|| token.to_string())
    })
}

#[cfg(target_os = "macos")]
fn macos_pf_flush_anchor() {
    let _ = Command::new("/sbin/pfctl")
        .args(["-a", PF_DNS_ANCHOR, "-F", "all"])
        .output()
        .map_err(|e| debug!("清理 macOS PF DNS anchor 失败：{e}"));
}

#[cfg(target_os = "macos")]
fn macos_pf_release_token(token: Option<&str>) {
    let Some(token) = token else {
        return;
    };
    let _ = Command::new("/sbin/pfctl")
        .args(["-X", token])
        .output()
        .map_err(|e| debug!("释放 macOS PF enable token 失败：{e}"));
}

#[cfg(target_os = "macos")]
pub(super) fn command_output_message(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        if stdout.is_empty() {
            output.status.to_string()
        } else {
            stdout
        }
    } else {
        stderr
    }
}
