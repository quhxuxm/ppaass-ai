use super::*;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

const MACOS_PF_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MACOS_PF_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub(crate) const DIRECT_DNS_PORT_FIRST: u16 = 54_000;
pub(crate) const DIRECT_DNS_PORT_LAST: u16 = 54_999;

pub(super) struct MacosPfDnsGuard {
    token: Option<String>,
    cleaned: bool,
}

#[cfg(target_os = "macos")]
impl MacosPfDnsGuard {
    pub(super) fn install(
        tun_if_index: u32,
        dns_capture_target: Ipv4Addr,
        dns_servers: &[SystemDnsServer],
        default_interfaces: &[String],
        pf_token_observer: &mut dyn FnMut(Option<&str>) -> Result<()>,
    ) -> Result<Self> {
        let tun_if_name = interface_name_for_index(Some(tun_if_index)).ok_or_else(|| {
            AgentError::Connection(format!(
                "无法根据 if_index={tun_if_index} 获取 macOS TUN 接口名，不能安装 PF DNS 捕获规则"
            ))
        })?;
        let rules = macos_pf_dns_rules(
            &tun_if_name,
            dns_capture_target,
            dns_servers,
            default_interfaces,
        );
        if rules.trim().is_empty() {
            return Err(AgentError::Connection(
                "macOS TUN proxy_dns 未发现可用的 IPv4 DNS 或物理出口接口，不能安装 PF DNS 捕获规则"
                    .to_string(),
            ));
        }

        let mut token = match macos_pf_enable() {
            Ok(token) => Some(token),
            Err(e) => {
                return Err(pf_install_error(
                    format!("启用 macOS PF 以捕获 scoped DNS 失败：{e}"),
                    &mut None,
                ));
            }
        };
        if let Err(observer_error) = pf_token_observer(token.as_deref()) {
            let rollback_error = cleanup_pf_state(&mut token).err();
            let message = match rollback_error {
                Some(rollback_error) => format!(
                    "持久化 macOS PF enable token 失败：{observer_error}；释放未持久化 token 也失败：{rollback_error}"
                ),
                None => format!("持久化 macOS PF enable token 失败：{observer_error}"),
            };
            return Err(AgentError::Connection(message));
        }

        let path = std::env::temp_dir().join(format!(
            "ppaass-tun-dns-pf-{}-{}.conf",
            std::process::id(),
            now_unix_secs()
        ));
        if let Err(e) = fs::write(&path, &rules) {
            return Err(pf_install_error(
                format!("写入 macOS PF DNS 规则失败：{}：{e}", path.display()),
                &mut token,
            ));
        }

        let load_result = Command::new("/sbin/pfctl")
            .args(["-a", PF_DNS_ANCHOR, "-f"])
            .arg(&path)
            .output();
        let _ = fs::remove_file(&path);

        match load_result {
            Ok(output) if output.status.success() => {
                info!("已安装 macOS scoped DNS 捕获规则（不修改系统 DNS）");
                Ok(Self {
                    token,
                    cleaned: false,
                })
            }
            Ok(output) => {
                let message = command_output_message(&output);
                Err(pf_install_error(
                    format!("安装 macOS PF DNS 捕获规则失败：{message}"),
                    &mut token,
                ))
            }
            Err(e) => Err(pf_install_error(
                format!("运行 pfctl 安装 DNS 捕获规则失败：{e}"),
                &mut token,
            )),
        }
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        macos_pf_flush_anchor()
            .map_err(|e| AgentError::Connection(format!("清理 macOS PF DNS anchor 失败：{e}")))?;
        macos_pf_release_token(self.token.as_deref())
            .map_err(|e| AgentError::Connection(format!("释放 macOS PF enable token 失败：{e}")))?;
        self.token = None;
        self.cleaned = true;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosPfDnsGuard {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            warn!("macOS PF DNS guard 析构清理失败：{err}");
        }
    }
}

#[cfg(target_os = "macos")]
fn pf_install_error(message: String, token: &mut Option<String>) -> AgentError {
    match cleanup_pf_state(token) {
        Ok(()) => AgentError::Connection(message),
        Err(cleanup_error) => AgentError::Connection(format!(
            "{message}；PF 回滚失败，保留错误供 helper 拒绝启动：{cleanup_error}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn cleanup_pf_state(token: &mut Option<String>) -> std::io::Result<()> {
    macos_pf_flush_anchor()?;
    macos_pf_release_token(token.as_deref())?;
    *token = None;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn macos_pf_dns_rules(
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
                "pass out quick on {interface_name} inet proto udp from any port {DIRECT_DNS_PORT_FIRST}:{DIRECT_DNS_PORT_LAST} to {dns_ip} port = 53 keep state\n"
            ));
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
fn macos_pf_enable() -> std::io::Result<String> {
    let mut command = Command::new("/sbin/pfctl");
    command.arg("-E");
    let output = run_macos_pf_command(command)?;
    if !output.status.success() {
        return Err(std::io::Error::other(command_output_message(&output)));
    }
    parse_pf_token(&output).ok_or_else(|| {
        std::io::Error::other(format!(
            "pfctl -E 成功但未返回可持久化的 enable token：{}",
            command_output_message(&output)
        ))
    })
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
fn macos_pf_flush_anchor() -> std::io::Result<()> {
    let mut command = Command::new("/sbin/pfctl");
    command.args(["-a", PF_DNS_ANCHOR, "-F", "all"]);
    let output = run_macos_pf_command(command)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(command_output_message(&output)))
    }
}

pub(in crate::tun_handler) fn cleanup_macos_pf_dns_capture_with_token(
    token: Option<&str>,
) -> Result<()> {
    macos_pf_flush_anchor()
        .map_err(|e| AgentError::Connection(format!("清理 macOS PF DNS anchor 失败：{e}")))?;
    macos_pf_release_token(token)
        .map_err(|e| AgentError::Connection(format!("释放 macOS PF enable token 失败：{e}")))
}

#[cfg(target_os = "macos")]
fn macos_pf_release_token(token: Option<&str>) -> std::io::Result<()> {
    let Some(token) = token else {
        return Ok(());
    };
    let mut command = Command::new("/sbin/pfctl");
    command.args(["-X", token]);
    let output = run_macos_pf_command(command)?;
    if output.status.success() {
        Ok(())
    } else {
        let message = command_output_message(&output);
        if pf_token_already_released(&message) {
            debug!("macOS PF enable token 已不存在，按幂等清理处理：{message}");
            Ok(())
        } else {
            Err(std::io::Error::other(message))
        }
    }
}

#[cfg(target_os = "macos")]
pub fn pf_token_already_released(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("invalid argument")
        || message.contains("no such")
        || message.contains("not found")
}

#[cfg(target_os = "macos")]
fn run_macos_pf_command(mut command: Command) -> std::io::Result<std::process::Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(_) => return child.wait_with_output(),
            None if started.elapsed() >= MACOS_PF_COMMAND_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "pfctl command timed out after {} seconds",
                        MACOS_PF_COMMAND_TIMEOUT.as_secs()
                    ),
                ));
            }
            None => thread::sleep(MACOS_PF_COMMAND_POLL_INTERVAL),
        }
    }
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
