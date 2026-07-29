use super::*;

#[cfg(target_os = "macos")]
#[test]
fn macos_uses_pf_instead_of_dns_capture_host_routes() {
    assert!(!should_install_dns_capture_host_routes());
}

#[cfg(target_os = "macos")]
#[test]
fn parses_macos_route_get_gateway_even_when_interface_is_unknown() {
    let output = r#"
   route to: 140.82.30.214
destination: 140.82.30.214
    gateway: 192.168.31.1
  interface: test999
"#;

    assert_eq!(
        parse_macos_route_get_next_hop(output),
        Some((Some(IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1))), None))
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_delete_split_default_uses_netmask_not_cidr() {
    let record = RouteRecord {
        kind: RouteKind::Ipv4SplitDefault,
        destination: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        prefix: 1,
        gateway: None,
        if_name: Some("utun8".to_string()),
        if_index: Some(19),
    };

    let command = macos_route_delete_command(&record, None, false);
    let args = command_args(&command);

    assert_eq!(
        args,
        vec![
            "-n",
            "delete",
            "-inet",
            "-net",
            "128.0.0.0",
            "-netmask",
            "128.0.0.0"
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_delete_dns_capture_route_can_scope_to_utun() {
    let record = RouteRecord {
        kind: RouteKind::DnsCapture,
        destination: IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1)),
        prefix: 32,
        gateway: None,
        if_name: Some("utun8".to_string()),
        if_index: Some(19),
    };

    let command = macos_route_delete_command(&record, Some("utun8"), false);
    let args = command_args(&command);

    assert_eq!(
        args,
        vec![
            "-n",
            "delete",
            "-inet",
            "-host",
            "-ifscope",
            "utun8",
            "192.168.31.1"
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_keeps_scoped_default_bypass_records() {
    let record = RouteRecord {
        kind: RouteKind::MacosScopedDefaultBypass,
        destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix: 0,
        gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1))),
        if_name: Some("en0".to_string()),
        if_index: Some(11),
    };

    assert!(!should_delete_recorded_route(&record));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_scoped_default_change_updates_ifscope_gateway() {
    let command = macos_scoped_default_command(
        "change",
        "en0",
        IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)),
        false,
    );
    let args = command_args(&command);

    assert_eq!(
        args,
        vec![
            "-n",
            "change",
            "-ifscope",
            "en0",
            "-net",
            "default",
            "192.168.50.1"
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_pf_dns_rules_use_default_interface_when_scutil_omits_scope() {
    let dns_servers = vec![SystemDnsServer {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1)),
        interface_name: None,
    }];

    let rules = macos_pf_dns_rules(
        "utun9",
        Ipv4Addr::new(10, 10, 10, 2),
        &dns_servers,
        &["en0".to_string()],
    );

    assert!(rules.contains("pass out quick on en0"));
    assert!(rules.contains("route-to (utun9 10.10.10.2)"));
    assert!(rules.contains("to 192.168.31.1 port = 53"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_pf_dns_rules_prefer_scutil_scope_over_default_interface() {
    let dns_servers = vec![SystemDnsServer {
        ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        interface_name: Some("en1".to_string()),
    }];

    let rules = macos_pf_dns_rules(
        "utun9",
        Ipv4Addr::new(10, 10, 10, 2),
        &dns_servers,
        &["en0".to_string()],
    );

    assert!(rules.contains("pass out quick on en1"));
    assert!(!rules.contains("pass out quick on en0"));
}

#[cfg(target_os = "macos")]
fn command_args(command: &Command) -> Vec<String> {
    command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}
