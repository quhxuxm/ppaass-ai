use desktop_agent_ui::auth::validate_managed_proxy_addresses;

fn addresses(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

#[test]
fn accepts_supported_hosts_and_ports() {
    for value in [
        "proxy.example.com:443",
        "127.0.0.1:1",
        "[2001:db8::1]:65535",
    ] {
        assert!(validate_managed_proxy_addresses(&addresses(&[value]), false).is_ok());
    }
}

#[test]
fn rejects_empty_duplicate_url_path_and_invalid_ports() {
    assert!(validate_managed_proxy_addresses(&[], false).is_err());
    assert!(validate_managed_proxy_addresses(&[], true).is_ok());
    for values in [
        vec!["proxy.example.com:443", "PROXY.example.com:443"],
        vec!["https://proxy.example.com:443"],
        vec!["proxy.example.com/path:443"],
        vec!["proxy.example.com:0"],
        vec!["proxy.example.com:65536"],
        vec!["2001:db8::1:443"],
    ] {
        assert!(validate_managed_proxy_addresses(&addresses(&values), false).is_err());
    }
}

#[test]
fn rejects_invalid_ascii_hostnames() {
    for host in [
        "-bad.example",
        "bad-.example",
        "bad..example",
        "bad_example",
    ] {
        let value = format!("{host}:443");
        assert!(validate_managed_proxy_addresses(&[value], false).is_err());
    }
    let long_label = "a".repeat(64);
    assert!(
        validate_managed_proxy_addresses(&[format!("{long_label}.example:443")], false).is_err()
    );
}
