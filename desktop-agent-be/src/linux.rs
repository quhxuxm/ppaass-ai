//! Linux TUN prerequisites shared by the CLI and embedded desktop agent.

use std::fs::{self, OpenOptions};

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_NET_RAW: u64 = 1 << 13;

/// Check effective capabilities, rather than UID: a root process in a container
/// can lack these capabilities, while a normal user can receive them via setcap.
pub fn validate_tun_capabilities(process_status: &str) -> Result<(), String> {
    let effective = process_status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| "无法读取 Linux 进程的有效 capabilities，不能确认 TUN 权限".to_string())?;
    let required = CAP_NET_ADMIN | CAP_NET_RAW;
    if effective & required != required {
        return Err(
            "Linux TUN 需要 CAP_NET_ADMIN（网卡与路由）和 CAP_NET_RAW（物理网卡绑定）。请为安装后的 Agent 可执行文件授予 cap_net_admin,cap_net_raw+ep 并重新启动应用；也可关闭 TUN 使用 HTTP/SOCKS5 代理。操作步骤见 docs/SETUP.md。"
                .to_string(),
        );
    }
    Ok(())
}

/// Fail before changing routes or launching tasks. Never relaunch the GUI with
/// sudo: the WebView and account session must remain in the desktop user's session.
pub fn ensure_tun_privileges() -> Result<(), String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("读取 Linux TUN 权限失败：{error}"))?;
    validate_tun_capabilities(&status)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|error| {
            format!("无法打开 Linux TUN 设备 /dev/net/tun：{error}；请确认已加载 tun 模块且当前用户可以访问该设备")
        })?;
    Ok(())
}
