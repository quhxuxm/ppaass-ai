use super::*;

fn record(
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    if_index: Option<u32>,
) -> RouteRecord {
    RouteRecord {
        kind: RouteKind::Ipv4SplitDefault,
        destination,
        prefix,
        gateway,
        if_name: None,
        if_index,
    }
}

#[test]
fn matches_windows_unspecified_ipv4_gateway_for_on_link_route() {
    let record = record(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None, Some(42));
    let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)
        .with_if_index(42)
        .with_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    assert!(record.matches_route(&route));
}

#[test]
fn matches_windows_unspecified_ipv6_gateway_for_on_link_route() {
    let record = record(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, None, Some(42));
    let route = Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1)
        .with_if_index(42)
        .with_gateway(IpAddr::V6(Ipv6Addr::UNSPECIFIED));

    assert!(record.matches_route(&route));
}

#[test]
fn rejects_different_real_gateway() {
    let record = record(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        32,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        Some(7),
    );
    let route = Route::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 32)
        .with_if_index(7)
        .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));

    assert!(!record.matches_route(&route));
}

#[test]
fn matches_route_by_interface_name_when_index_changes() {
    let mut record = record(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None, Some(42));
    record.if_name = Some("utun9".to_string());
    let mut route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).with_if_index(77);
    route = route.with_if_name("utun9".to_string());

    assert!(record.matches_route(&route));
}

#[test]
fn detects_dns_capture_route_when_dns_is_default_gateway() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));

    assert!(dns_capture_route_targets_default_gateway(
        gateway,
        Some(gateway),
        None
    ));
}

#[test]
fn allows_dns_capture_route_when_dns_is_not_default_gateway() {
    let dns = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));

    assert!(!dns_capture_route_targets_default_gateway(
        dns,
        Some(gateway),
        None
    ));
}

#[cfg(windows)]
#[test]
fn windows_captures_default_gateway_dns_route() {
    assert!(should_capture_default_gateway_dns_route());
}

#[cfg(not(windows))]
#[test]
fn non_windows_keeps_default_gateway_dns_route_conservative() {
    assert!(!should_capture_default_gateway_dns_route());
}

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
