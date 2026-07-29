#[cfg(target_os = "macos")]
use super::*;

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn install_macos_scoped_default_bypass(
    default_v4_gw: Option<IpAddr>,
    default_v4_if: Option<u32>,
    default_v6_gw: Option<IpAddr>,
    default_v6_if: Option<u32>,
) {
    if let (Some(gw), Some(if_idx)) = (default_v4_gw, default_v4_if)
        && let Some(if_name) = interface_name_for_index(Some(if_idx))
    {
        install_one_macos_scoped_default(&if_name, gw, false);
    } else {
        debug!("跳过 macOS IPv4 scoped default bypass：默认网关或接口缺失");
    }

    if let (Some(gw), Some(if_idx)) = (default_v6_gw, default_v6_if)
        && let Some(if_name) = interface_name_for_index(Some(if_idx))
    {
        install_one_macos_scoped_default(&if_name, gw, true);
    } else {
        debug!("跳过 macOS IPv6 scoped default bypass：默认网关或接口缺失");
    }
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn refresh_macos_scoped_default_bypass() {
    let mut mgr = match RouteManager::new() {
        Ok(mgr) => mgr,
        Err(e) => {
            warn!("刷新 macOS scoped default bypass 时 RouteManager 初始化失败：{e}");
            return;
        }
    };
    let routes = match mgr.list() {
        Ok(routes) => routes,
        Err(e) => {
            warn!("刷新 macOS scoped default bypass 时无法列出当前路由：{e}");
            return;
        }
    };
    let (default_v4_gw, default_v4_if) = find_default_route(&routes, false);
    let (default_v6_gw, default_v6_if) = find_default_route(&routes, true);
    install_macos_scoped_default_bypass(default_v4_gw, default_v4_if, default_v6_gw, default_v6_if);
}

#[cfg(not(target_os = "macos"))]
pub(in crate::tun_handler::route) fn refresh_macos_scoped_default_bypass() {}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn install_one_macos_scoped_default(
    if_name: &str,
    gateway: IpAddr,
    is_ipv6: bool,
) {
    // 形如：route -n add -ifscope en0 -net default 192.168.31.1
    let mut cmd = macos_scoped_default_command("add", if_name, gateway, is_ipv6);

    match cmd.output() {
        Ok(out) if out.status.success() => {
            info!(
                "已安装 macOS scoped default bypass：ifscope={if_name} gateway={gateway}；关闭 TUN 时保留该路由"
            );
        }
        Ok(out) => {
            let msg = command_output_message(&out);
            // 待机恢复或 Wi-Fi 切换后，ifscope default 可能仍存在但网关已过期。
            // add 返回已存在时主动更新下一跳，避免 IP_BOUND_IF 直连继续查到旧网关。
            if route_add_error_is_already_exists(&msg) {
                replace_one_macos_scoped_default(if_name, gateway, is_ipv6);
            } else {
                warn!(
                    "安装 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{msg}"
                );
            }
        }
        Err(e) => warn!("运行 route add -ifscope 安装 macOS scoped default bypass 失败：{e}"),
    }
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn replace_one_macos_scoped_default(
    if_name: &str,
    gateway: IpAddr,
    is_ipv6: bool,
) {
    let mut change = macos_scoped_default_command("change", if_name, gateway, is_ipv6);
    match change.output() {
        Ok(out) if out.status.success() => {
            info!("已刷新 macOS scoped default bypass：ifscope={if_name} gateway={gateway}");
            return;
        }
        Ok(out) => {
            debug!(
                "route change 刷新 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{}",
                command_output_message(&out)
            );
        }
        Err(e) => debug!(
            "运行 route change 刷新 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{e}"
        ),
    }

    let mut delete = macos_scoped_default_delete_command(if_name, is_ipv6);
    match delete.output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => debug!(
            "route delete 清理旧 macOS scoped default bypass 失败 ifscope={if_name}：{}",
            command_output_message(&out)
        ),
        Err(e) => debug!(
            "运行 route delete 清理旧 macOS scoped default bypass 失败 ifscope={if_name}：{e}"
        ),
    }

    let mut add = macos_scoped_default_command("add", if_name, gateway, is_ipv6);
    match add.output() {
        Ok(out) if out.status.success() => {
            info!("已重建 macOS scoped default bypass：ifscope={if_name} gateway={gateway}");
        }
        Ok(out) => warn!(
            "重建 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{}",
            command_output_message(&out)
        ),
        Err(e) => warn!(
            "运行 route add 重建 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{e}"
        ),
    }
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn macos_scoped_default_command(
    action: &str,
    if_name: &str,
    gateway: IpAddr,
    is_ipv6: bool,
) -> Command {
    let mut command = Command::new("/sbin/route");
    command.arg("-n").arg(action);
    if is_ipv6 {
        command.arg("-inet6");
    }
    command.args(["-ifscope", if_name, "-net", "default", &gateway.to_string()]);
    command
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn macos_scoped_default_delete_command(
    if_name: &str,
    is_ipv6: bool,
) -> Command {
    let mut command = Command::new("/sbin/route");
    command.arg("-n").arg("delete");
    if is_ipv6 {
        command.arg("-inet6");
    }
    command.args(["-ifscope", if_name, "-net", "default"]);
    command
}
