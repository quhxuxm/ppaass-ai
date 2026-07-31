use super::*;

#[test]
fn upsert_toml_bool_updates_or_adds_nested_key() {
    let updated = upsert_toml_bool(
        r#"listen_addr = "0.0.0.0:10080"

[tun]
enabled = false
name = "ppaass-tun"
"#,
        "tun",
        "enabled",
        true,
    );
    assert!(updated.contains("[tun]\nenabled = true\nname = \"ppaass-tun\""));

    let inserted = upsert_toml_bool("username = \"user1\"\n", "tun", "enabled", true);
    assert!(inserted.contains("[tun]\nenabled = true"));
}

#[test]
fn enforce_managed_identity_overrides_quoted_keys_and_escapes_paths() {
    let raw = concat!(
        "\"username\" = \"attacker\"\n",
        "\"private_key_path\" = \"attacker.pem\"\n\n",
        "[tun]\n",
        "enabled = false\n",
    );
    let key_path = std::path::Path::new(r#"C:\Users\me\private "key".pem"#);
    let updated =
        enforce_managed_identity(raw, "new-user", key_path, "https://managed.example.com").unwrap();
    let summary = summarize_config(&updated).unwrap();
    assert_eq!(summary.username, "new-user");
    assert_eq!(summary.private_key_path, r#"C:\Users\me\private "key".pem"#);
    assert!(updated.contains("[tun]\nenabled = false"));
    assert!(!updated.contains("attacker"));
}

#[test]
fn redact_managed_identity_removes_credentials_from_ui_config() {
    let raw = concat!(
        "# identity is managed by Proxy Registry\n",
        "\"username\" = \"alice\"\n",
        "\"private_key_path\" = \"/secret/managed.pem\"\n",
        "\"proxy_registry_url\" = \"https://hidden.example.com\"\n",
        "listen_addr = \"127.0.0.1:10080\"\n\n",
        "[tun]\n",
        "enabled = false\n",
    );
    let loaded = LoadedAgentConfig {
        path: "/tmp/agent.toml".to_string(),
        raw: raw.to_string(),
        summary: summarize_config(raw).unwrap(),
    };

    let redacted = redact_managed_identity(loaded).unwrap();
    assert!(!redacted.raw.contains("username"));
    assert!(!redacted.raw.contains("private_key_path"));
    assert!(!redacted.raw.contains("proxy_registry_url"));
    assert!(!redacted.raw.contains("hidden.example.com"));
    assert!(!redacted.raw.contains("/secret/managed.pem"));
    assert!(redacted.raw.contains("listen_addr = \"127.0.0.1:10080\""));
    assert!(redacted.raw.contains("[tun]\nenabled = false"));
    assert!(redacted.summary.username.is_empty());
    assert!(redacted.summary.private_key_path.is_empty());

    let serialized = serde_json::to_string(&redacted).unwrap();
    assert!(!serialized.contains("username"));
    assert!(!serialized.contains("private_key_path"));
    assert!(!serialized.contains("proxy_registry_url"));
    assert!(!serialized.contains("hidden.example.com"));
    assert!(!serialized.contains("/secret/managed.pem"));
}

#[test]
fn applies_managed_credentials_without_changing_other_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.toml");
    fs::write(
            &path,
            "listen_addr = \"127.0.0.1:10080\"\nproxy_registry_url = \"https://hidden.example.com\"\nusername = \"old\"\nprivate_key_path = \"old.pem\"\n\n[tun]\nenabled = false\n",
        )
        .unwrap();
    let key_path = directory.path().join("credentials/new.pem");
    let loaded = apply_managed_credentials_to_config(&path, "alice", &key_path).unwrap();
    assert_eq!(loaded.summary.username, "alice");
    assert_eq!(loaded.summary.private_key_path, key_path.to_string_lossy());
    assert_eq!(loaded.summary.listen_addr, "127.0.0.1:10080");
    assert!(!loaded.summary.tun_enabled);
    assert_eq!(
        proxy_registry_url_from_config(&path).unwrap(),
        "https://hidden.example.com"
    );
}

#[test]
fn managed_identity_round_trip_keeps_secret_on_disk_but_not_in_ui() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.toml");
    let key_path = directory.path().join("credentials/managed.pem");
    fs::write(
            &path,
            "listen_addr = \"127.0.0.1:10080\"\nproxy_registry_url = \"https://hidden.example.com\"\nusername = \"old\"\nprivate_key_path = \"old.pem\"\n",
        )
        .unwrap();

    let loaded = apply_managed_credentials_to_config(&path, "alice", &key_path).unwrap();
    let redacted = redact_managed_identity(loaded).unwrap();
    assert!(!redacted.raw.contains("private_key_path"));
    assert!(!redacted.raw.contains("proxy_registry_url"));

    let edited = format!(
        "{}proxy_registry_url = \"https://attacker.example.com\"\ntransport_mode = \"tcp\"\n",
        redacted.raw
    );
    let enforced =
        enforce_managed_identity(&edited, "alice", &key_path, "https://hidden.example.com")
            .unwrap();
    write_config_file(&path, &enforced).unwrap();
    let persisted = load_config_from_path(&path).unwrap();
    assert_eq!(persisted.summary.username, "alice");
    assert_eq!(
        persisted.summary.private_key_path,
        key_path.to_string_lossy()
    );
    assert_eq!(persisted.summary.transport_mode, "tcp");
    assert_eq!(
        proxy_registry_url_from_config(&path).unwrap(),
        "https://hidden.example.com"
    );
    assert!(!persisted.raw.contains("attacker.example.com"));
}

#[test]
fn clearing_managed_credentials_preserves_hidden_proxy_registry_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("agent.toml");
    fs::write(
            &path,
            "proxy_registry_url = \"https://hidden.example.com\"\nusername = \"alice\"\nprivate_key_path = \"credentials/managed.pem\"\ntransport_mode = \"tcp\"\n",
        )
        .unwrap();

    clear_managed_credentials_from_config(&path).unwrap();

    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("username"));
    assert!(!raw.contains("private_key_path"));
    assert!(raw.contains("proxy_registry_url = \"https://hidden.example.com\""));
    assert!(raw.contains("transport_mode = \"tcp\""));
}

#[test]
fn proxy_registry_url_must_exist_in_desktop_agent_config() {
    let directory = tempfile::tempdir().unwrap();
    let configured = directory.path().join("configured.toml");
    let missing = directory.path().join("missing.toml");
    fs::write(
        &configured,
        "proxy_registry_url = \"http://127.0.0.1:8787\"\n",
    )
    .unwrap();
    fs::write(&missing, "listen_addr = \"127.0.0.1:10080\"\n").unwrap();

    assert_eq!(
        proxy_registry_url_from_config(&configured).unwrap(),
        "http://127.0.0.1:8787"
    );
    assert!(proxy_registry_url_from_config(&missing).is_err());
}

#[test]
fn formal_bundled_config_keeps_tun_off_with_proxy_dns_ready() {
    let summary = summarize_config(include_str!("../../../../../config/agent.toml")).unwrap();

    assert!(!summary.tun_enabled);
    assert!(summary.tun_proxy_dns);
}
