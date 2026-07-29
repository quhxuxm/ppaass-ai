use super::*;

pub(crate) fn summarize_config(raw: &str) -> Result<AgentConfigSummary, String> {
    let value = toml::from_str::<Value>(raw).map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    if value_at(&value, &["quic_connection_pool_size"]).is_some() {
        return Err(
            "配置字段 quic_connection_pool_size 已移除，请使用 udp_session_pool_size".to_string(),
        );
    }
    for (removed, current) in [
        ("helper_enabled", "macos_helper_enabled"),
        ("helper_socket", "macos_helper_socket"),
        (
            "helper_fallback_to_privilege",
            "macos_helper_fallback_to_privilege",
        ),
    ] {
        if value_at(&value, &["tun", removed]).is_some() {
            return Err(format!(
                "配置字段 tun.{removed} 已移除，请使用 tun.{current}"
            ));
        }
    }
    let transport_mode =
        normalize_transport_mode(str_at(&value, &["transport_mode"]).unwrap_or("udp"))?;
    let tun_quic_policy = normalize_quic_policy(
        string_at(&value, &["tun", "quic_policy"])
            .as_deref()
            .unwrap_or("allow"),
    );
    let runtime_threads = int_at(&value, &["runtime_threads"])
        .filter(|value| *value > 0)
        .map(|value| value as usize);

    Ok(AgentConfigSummary {
        listen_addr: string_or(&value, &["listen_addr"], "0.0.0.0:10080"),
        proxy_addrs: string_array_at(&value, &["proxy_addrs"]),
        username: string_or(&value, &["username"], ""),
        private_key_path: string_or(&value, &["private_key_path"], ""),
        transport_mode,
        udp_session_pool_size: int_at(&value, &["udp_session_pool_size"])
            .unwrap_or(DEFAULT_UDP_SESSION_POOL_SIZE)
            .clamp(1, MAX_UDP_SESSION_POOL_SIZE) as usize,
        connect_timeout_secs: int_at(&value, &["connect_timeout_secs"]).unwrap_or(30),
        compression_mode: string_or(&value, &["compression_mode"], "none"),
        log_level: string_or(&value, &["log_level"], "info"),
        log_dir: string_at(&value, &["log_dir"]),
        log_file: string_or(&value, &["log_file"], "desktop-agent.log"),
        runtime_threads,
        effective_runtime_threads: runtime_threads.unwrap_or_else(default_runtime_threads),
        udp_yamux_sessions: int_at(&value, &["yamux", "udp", "sessions"])
            .unwrap_or(DEFAULT_UDP_YAMUX_SESSIONS) as usize,
        udp_yamux_max_streams_per_session: int_at(
            &value,
            &["yamux", "udp", "max_streams_per_session"],
        )
        .unwrap_or(256) as usize,
        udp_yamux_open_stream_timeout_secs: int_at(
            &value,
            &["yamux", "udp", "open_stream_timeout_secs"],
        )
        .unwrap_or(10),
        udp_yamux_keepalive_interval_secs: int_at(
            &value,
            &["yamux", "udp", "keepalive_interval_secs"],
        )
        .unwrap_or(30),
        udp_yamux_connection_write_timeout_secs: int_at(
            &value,
            &["yamux", "udp", "connection_write_timeout_secs"],
        )
        .unwrap_or(10),
        udp_yamux_stream_window_size_kb: int_at(&value, &["yamux", "udp", "stream_window_size_kb"])
            .unwrap_or(8192) as usize,
        tun_enabled: bool_at(&value, &["tun", "enabled"]).unwrap_or(false),
        tun_name: string_or(&value, &["tun", "name"], default_tun_name()),
        tun_ipv4: string_or(&value, &["tun", "ipv4"], "10.10.10.1/24"),
        tun_mtu: int_at(&value, &["tun", "mtu"]).unwrap_or(1500),
        tun_proxy_udp: bool_at(&value, &["tun", "proxy_udp"]).unwrap_or(true),
        tun_proxy_dns: bool_at(&value, &["tun", "proxy_dns"]).unwrap_or(true),
        tun_quic_policy,
        tun_packet_capture_file: string_or(
            &value,
            &["tun", "packet_capture", "file"],
            "captures/ppaass-tun.pcap",
        ),
        direct_mode: string_or(&value, &["direct_access", "mode"], "proxy_all"),
        direct_rules: string_array_at(&value, &["direct_access", "rules"]),
    })
}

pub(crate) fn default_runtime_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
}

pub(crate) fn config_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if cfg!(debug_assertions) {
        for dir in ancestor_dirs().into_iter().chain(deployed_agent_dirs()) {
            push_unique_path(&mut dirs, dir);
        }
    } else {
        for dir in deployed_agent_dirs().into_iter().chain(ancestor_dirs()) {
            push_unique_path(&mut dirs, dir);
        }
    }
    dirs
}

pub(crate) fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path)?
        .as_str()
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    str_at(value, path).map(ToOwned::to_owned)
}

pub(crate) fn string_or(value: &Value, path: &[&str], default: &str) -> String {
    str_at(value, path).unwrap_or(default).to_string()
}

pub(crate) fn int_at(value: &Value, path: &[&str]) -> Option<u64> {
    let value = value_at(value, path)?.as_integer()?;
    if value >= 0 {
        Some(value as u64)
    } else {
        None
    }
}

pub(crate) fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path)?.as_bool()
}

pub(crate) fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    let Some(items) = array_at(value, path) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

pub(crate) fn normalize_quic_policy(value: &str) -> String {
    match value {
        "allow" | "block" => value.to_string(),
        _ => "allow".to_string(),
    }
}

pub(crate) fn normalize_transport_mode(value: &str) -> Result<String, String> {
    match value {
        "auto" | "udp" | "tcp" => Ok(value.to_string()),
        _ => Err(format!(
            "transport_mode 只支持 auto、udp 或 tcp，当前值为 {value:?}"
        )),
    }
}

pub(crate) fn array_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a [Value]> {
    let items = value_at(value, path)?.as_array()?;
    Some(items.as_slice())
}

pub(crate) fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}
