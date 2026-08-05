use std::path::PathBuf;

use desktop_agent_ui::config::{
    loaded_config_from_raw, merge_config_summary, prepare_config_for_account, summarize_config,
    validate_config_update_permissions,
};
use desktop_agent_ui::models::{
    AgentAuthAccount, AGENT_EGRESS_EDIT_PERMISSION, AGENT_RUNTIME_THREADS_EDIT_PERMISSION,
};

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
