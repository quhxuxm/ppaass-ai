use toml_edit::Array;

use super::*;
use crate::models::{
    AgentAuthAccount, AGENT_EGRESS_EDIT_PERMISSION, AGENT_PACKET_CAPTURE_PERMISSION,
    AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
};
use crate::runtime::AgentRuntime;

pub(crate) fn prepare_config_for_account(
    loaded: LoadedAgentConfig,
    account: &AgentAuthAccount,
) -> Result<LoadedAgentConfig, String> {
    let (loaded, _) = enforce_loaded_config_for_account(loaded, account)?;
    let mut loaded = redact_managed_identity(loaded)?;
    if account.role != "admin" {
        loaded.raw.clear();
    }
    Ok(loaded)
}

#[cfg(test)]
pub(crate) fn validate_config_update_permissions(
    account: &AgentAuthAccount,
    existing_raw: &str,
    candidate_raw: &str,
) -> Result<(), String> {
    let existing = summarize_config(existing_raw)?;
    let candidate = summarize_config(candidate_raw)?;
    validate_config_summary_update_permissions(account, &existing, &candidate)
}

pub(crate) fn validate_config_summary_update_permissions(
    account: &AgentAuthAccount,
    _existing: &AgentConfigSummary,
    candidate: &AgentConfigSummary,
) -> Result<(), String> {
    let mut normalized = candidate.clone();
    let applied = apply_account_config_defaults(&mut normalized, account)?;
    if applied.egress {
        return Err(format!("当前账号缺少权限：{AGENT_EGRESS_EDIT_PERMISSION}"));
    }
    if applied.runtime {
        return Err(format!(
            "当前账号缺少权限：{AGENT_RUNTIME_THREADS_EDIT_PERMISSION}"
        ));
    }
    if applied.packet_capture {
        return Err(format!(
            "当前账号缺少权限：{AGENT_PACKET_CAPTURE_PERMISSION}"
        ));
    }
    Ok(())
}

pub(crate) fn validate_config_candidate_against_trusted_baseline(
    runtime: &AgentRuntime,
    account: &AgentAuthAccount,
    candidate: &LoadedAgentConfig,
) -> Result<(), String> {
    let baseline = trusted_config_baseline(runtime)?;
    validate_config_summary_update_permissions(account, &baseline, &candidate.summary)
}

pub(crate) fn remember_trusted_config_baseline(
    runtime: &AgentRuntime,
    loaded: &LoadedAgentConfig,
) -> Result<(), String> {
    *runtime
        .trusted_config_baseline
        .lock()
        .map_err(|_| "受管配置基线锁已损坏".to_string())? = Some(loaded.summary.clone());
    Ok(())
}

fn trusted_config_baseline(runtime: &AgentRuntime) -> Result<AgentConfigSummary, String> {
    if let Some(baseline) = runtime
        .trusted_config_baseline
        .lock()
        .map_err(|_| "受管配置基线锁已损坏".to_string())?
        .clone()
    {
        return Ok(baseline);
    }
    let path = runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())?
        .clone()
        .or_else(locate_config_path)
        .ok_or_else(|| "找不到当前受管或默认 Agent 配置基线".to_string())?;
    Ok(load_config_from_path(&path)?.summary)
}

pub(crate) fn merge_config_summary(
    existing_raw: &str,
    summary: &AgentConfigSummary,
) -> Result<String, String> {
    let mut document = existing_raw
        .parse::<DocumentMut>()
        .map_err(|error| format!("配置 TOML 解析失败：{error}"))?;
    document["listen_addr"] = value(summary.listen_addr.clone());
    document["transport_mode"] = value(summary.transport_mode.clone());
    document["udp_session_pool_size"] = value(as_i64(summary.udp_session_pool_size)?);
    document["connect_timeout_secs"] = value(as_i64(summary.connect_timeout_secs)?);
    document["compression_mode"] = value(summary.compression_mode.clone());
    document["log_level"] = value(summary.log_level.clone());
    set_optional_string(&mut document, "log_dir", summary.log_dir.as_deref());
    document["log_file"] = value(summary.log_file.clone());
    set_optional_integer(&mut document, "runtime_threads", summary.runtime_threads)?;

    document["yamux"]["udp"]["sessions"] = value(as_i64(summary.udp_yamux_sessions)?);
    document["yamux"]["udp"]["max_streams_per_session"] =
        value(as_i64(summary.udp_yamux_max_streams_per_session)?);
    document["yamux"]["udp"]["open_stream_timeout_secs"] =
        value(as_i64(summary.udp_yamux_open_stream_timeout_secs)?);
    document["yamux"]["udp"]["keepalive_interval_secs"] =
        value(as_i64(summary.udp_yamux_keepalive_interval_secs)?);
    document["yamux"]["udp"]["connection_write_timeout_secs"] =
        value(as_i64(summary.udp_yamux_connection_write_timeout_secs)?);
    document["yamux"]["udp"]["stream_window_size_kb"] =
        value(as_i64(summary.udp_yamux_stream_window_size_kb)?);

    document["tun"]["enabled"] = value(summary.tun_enabled);
    document["tun"]["name"] = value(summary.tun_name.clone());
    document["tun"]["ipv4"] = value(summary.tun_ipv4.clone());
    document["tun"]["mtu"] = value(as_i64(summary.tun_mtu)?);
    document["tun"]["proxy_udp"] = value(summary.tun_proxy_udp);
    document["tun"]["proxy_dns"] = value(summary.tun_proxy_dns);
    document["tun"]["quic_policy"] = value(summary.tun_quic_policy.clone());
    document["tun"]["packet_capture"]["file"] = value(summary.tun_packet_capture_file.clone());

    document["direct_access"]["mode"] = value(summary.direct_mode.clone());
    document["direct_access"]["rules"] = value(string_array(&summary.direct_rules));
    let merged = document.to_string();
    summarize_config(&merged)?;
    Ok(merged)
}

fn string_array(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    array
}

fn set_optional_string(document: &mut DocumentMut, key: &str, input: Option<&str>) {
    match input {
        Some(input) => document[key] = value(input),
        None => {
            document.remove(key);
        }
    }
}

fn set_optional_integer(
    document: &mut DocumentMut,
    key: &str,
    input: Option<usize>,
) -> Result<(), String> {
    match input {
        Some(input) => document[key] = value(as_i64(input)?),
        None => {
            document.remove(key);
        }
    }
    Ok(())
}

fn as_i64<T>(value: T) -> Result<i64, String>
where
    T: TryInto<i64>,
{
    value
        .try_into()
        .map_err(|_| "配置整数超出 TOML 支持范围".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(role: &str, permissions: &[&str]) -> AgentAuthAccount {
        AgentAuthAccount {
            username: "alice".to_string(),
            display_name: None,
            avatar_url: None,
            role: role.to_string(),
            permissions: permissions
                .iter()
                .map(|permission| (*permission).to_string())
                .collect(),
            key_version: 1,
            expires_at: None,
        }
    }

    fn raw() -> String {
        [
            "listen_addr = \"0.0.0.0:10080\"",
            "transport_mode = \"udp\"",
            "udp_session_pool_size = 4",
            "connect_timeout_secs = 30",
            "compression_mode = \"none\"",
            "runtime_threads = 2",
            "log_level = \"info\"",
            "",
        ]
        .join("\n")
    }

    #[test]
    fn raw_config_is_admin_only_but_users_receive_safe_structured_config() {
        let mut sensitive_raw = raw();
        sensitive_raw.push_str("\n[tun]\nenabled = true\nname = \"sensitive-tun\"\n");
        let loaded = loaded_config_from_raw(PathBuf::from("agent.toml"), sensitive_raw).unwrap();
        let hidden = prepare_config_for_account(loaded.clone(), &account("user", &[])).unwrap();
        assert!(hidden.raw.is_empty());
        assert!(hidden.summary.tun_enabled);
        assert_eq!(hidden.summary.listen_addr, "0.0.0.0:10080");
        assert_eq!(hidden.summary.tun_name, "sensitive-tun");

        let serialized = serde_json::to_string(&hidden).unwrap();
        assert!(serialized.contains("sensitive-tun"));
        assert!(!serialized.contains("\"runtime_threads\":2"));

        let visible = prepare_config_for_account(loaded, &account("admin", &[])).unwrap();
        assert!(visible.raw.contains("listen_addr"));
    }

    #[test]
    fn restricted_config_fields_require_permissions_but_other_fields_remain_editable() {
        let existing = raw();
        let unrestricted = existing.replace(
            "listen_addr = \"0.0.0.0:10080\"",
            "listen_addr = \"127.0.0.1:10080\"",
        );
        assert!(validate_config_update_permissions(
            &account(
                "user",
                &[
                    AGENT_EGRESS_EDIT_PERMISSION,
                    AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
                ],
            ),
            &existing,
            &unrestricted
        )
        .is_ok());

        let egress = existing.replace("connect_timeout_secs = 30", "connect_timeout_secs = 45");
        assert!(
            validate_config_update_permissions(&account("user", &[]), &existing, &egress)
                .unwrap_err()
                .contains(AGENT_EGRESS_EDIT_PERMISSION)
        );
        assert!(validate_config_update_permissions(
            &account("user", &[AGENT_EGRESS_EDIT_PERMISSION]),
            &existing,
            &egress
        )
        .unwrap_err()
        .contains(AGENT_RUNTIME_THREADS_EDIT_PERMISSION));

        let threads = existing.replace("runtime_threads = 2", "runtime_threads = 4");
        assert!(
            validate_config_update_permissions(&account("admin", &[]), &existing, &threads).is_ok()
        );
    }

    #[test]
    fn structured_merge_preserves_unknown_and_managed_fields() {
        let existing = format!(
            "{}username = \"alice\"\nprivate_key_path = \"/secret/key.pem\"\nunknown = \"keep\"\n",
            raw()
        );
        let mut summary = summarize_config(&existing).unwrap();
        summary.log_level = "trace".to_string();
        let merged = merge_config_summary(&existing, &summary).unwrap();
        assert!(merged.contains("unknown = \"keep\""));
        assert!(merged.contains("private_key_path = \"/secret/key.pem\""));
        assert!(merged.contains("log_level = \"trace\""));
    }
}
