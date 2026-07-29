#[cfg(target_os = "macos")]
use super::guard::macos_scoped_default_command;
use super::guard::{
    local_network_bypass_routes, proxy_bypass_next_hop_from_routes,
    route_add_error_is_already_exists, route_list_contains_expected,
};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

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
fn route_state_persist_failure_is_fatal_and_keeps_rollback_record() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent_file = std::env::temp_dir().join(format!(
        "ppaass-route-state-parent-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&parent_file, b"not a directory").unwrap();
    let state_path = parent_file.join("routes.json");
    let state_path_string = state_path.to_string_lossy().into_owned();
    let mut lease = RouteLease::new(Some(&state_path_string));
    let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).with_if_index(42);

    let error = lease
        .record_installed(RouteKind::Ipv4SplitDefault, &route)
        .unwrap_err()
        .to_string();

    assert!(error.contains("拒绝继续修改路由表"));
    assert_eq!(lease.state.routes.len(), 1);
    assert!(lease.state.routes[0].matches_route(&route));
    fs::remove_file(parent_file).unwrap();
}

#[cfg(unix)]
#[test]
fn route_state_is_private_atomic_and_round_trips_adopted_bypass() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let state_path = std::env::temp_dir().join(format!(
        "ppaass-route-state-durable-{}-{}.json",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let state_path_string = state_path.to_string_lossy().into_owned();
    let mut lease = RouteLease::new(Some(&state_path_string));
    let route = Route::new(IpAddr::V4(Ipv4Addr::new(140, 82, 30, 214)), 32)
        .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1)))
        .with_if_index(11);

    lease
        .record_installed(RouteKind::ProxyBypass, &route)
        .unwrap();

    let metadata = fs::metadata(&state_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(persisted["routes"].as_array().unwrap().len(), 1);
    assert_eq!(persisted["routes"][0]["kind"], "ProxyBypass");
    assert_eq!(persisted["routes"][0]["destination"], "140.82.30.214");
    let temp_path = state_path.with_extension(format!("json.tmp.{}", std::process::id()));
    assert!(!temp_path.exists());

    lease.clear().unwrap();
    assert!(!state_path.exists());
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

#[test]
fn local_network_bypass_routes_keep_private_ranges_on_default_gateway() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));
    let routes = local_network_bypass_routes(Some(gateway), Some(11));

    let private_route = route_for(&routes, Ipv4Addr::new(192, 168, 0, 0), 16);
    assert_eq!(private_route.gateway(), Some(gateway));
    assert_eq!(private_route.if_index(), Some(11));

    let multicast_route = route_for(&routes, Ipv4Addr::new(224, 0, 0, 0), 4);
    assert_eq!(multicast_route.gateway(), None);
    assert_eq!(multicast_route.if_index(), Some(11));
}

#[test]
fn local_network_bypass_routes_skip_gateway_ranges_without_gateway() {
    let routes = local_network_bypass_routes(None, Some(11));

    assert!(
        !routes
            .iter()
            .any(|route| route.destination() == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)))
    );
    assert!(
        routes
            .iter()
            .any(|route| route.destination() == IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)))
    );
}

#[test]
fn local_network_bypass_record_matches_windows_on_link_gateway() {
    let record = RouteRecord {
        kind: RouteKind::LocalNetworkBypass,
        destination: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        prefix: 4,
        gateway: None,
        if_name: None,
        if_index: Some(11),
    };
    let route = Route::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4)
        .with_if_index(11)
        .with_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    assert!(record.matches_route(&route));
}

#[test]
fn route_add_error_already_exists_matches_windows_messages() {
    assert!(route_add_error_is_already_exists(
        "route: writing to routing socket: File exists"
    ));
    assert!(route_add_error_is_already_exists(
        "The object already exists. (os error 5010)"
    ));
    assert!(route_add_error_is_already_exists(
        "Cannot create a file when that file already exists. (os error 183)"
    ));
}

#[test]
fn existing_proxy_bypass_must_match_gateway_and_interface() {
    let proxy_ip = IpAddr::V4(Ipv4Addr::new(140, 82, 30, 214));
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));
    let expected = Route::new(proxy_ip, 32)
        .with_gateway(gateway)
        .with_if_index(11);
    let exact = Route::new(proxy_ip, 32)
        .with_gateway(gateway)
        .with_if_index(11);
    let wrong_gateway = Route::new(proxy_ip, 32)
        .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 31, 254)))
        .with_if_index(11);
    let wrong_interface = Route::new(proxy_ip, 32)
        .with_gateway(gateway)
        .with_if_index(12);

    assert!(route_list_contains_expected(
        RouteKind::ProxyBypass,
        &expected,
        &[exact]
    ));
    assert!(!route_list_contains_expected(
        RouteKind::ProxyBypass,
        &expected,
        &[wrong_gateway]
    ));
    assert!(!route_list_contains_expected(
        RouteKind::ProxyBypass,
        &expected,
        &[wrong_interface]
    ));
}

#[test]
fn existing_proxy_bypass_rejects_same_next_hop_for_another_host() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));
    let expected = Route::new(IpAddr::V4(Ipv4Addr::new(140, 82, 30, 214)), 32)
        .with_gateway(gateway)
        .with_if_index(11);
    let another_host = Route::new(IpAddr::V4(Ipv4Addr::new(140, 82, 30, 215)), 32)
        .with_gateway(gateway)
        .with_if_index(11);

    assert!(!route_list_contains_expected(
        RouteKind::ProxyBypass,
        &expected,
        &[another_host]
    ));
}

#[test]
fn proxy_bypass_next_hop_ignores_stale_host_and_split_routes() {
    let proxy_ip = IpAddr::V4(Ipv4Addr::new(140, 82, 30, 214));
    let stale_gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let current_gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));
    let routes = vec![
        Route::new(proxy_ip, 32)
            .with_gateway(stale_gateway)
            .with_if_index(7),
        Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1).with_if_index(99),
        Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .with_gateway(current_gateway)
            .with_if_index(11),
    ];

    assert_eq!(
        proxy_bypass_next_hop_from_routes(&routes, proxy_ip, Some(current_gateway), Some(11)),
        (Some(current_gateway), Some(11))
    );
}

#[test]
fn checked_proxy_resolution_allows_loopback_only_but_rejects_empty_config() {
    assert!(
        resolve_proxy_ips_checked(&["127.0.0.1:8080".to_string()])
            .unwrap()
            .is_empty()
    );
    assert!(resolve_proxy_ips_checked(&[]).is_err());
}

#[test]
fn checked_proxy_resolution_returns_non_loopback_literal() {
    assert_eq!(
        resolve_proxy_ips_checked(&["192.0.2.1:8080".to_string()]).unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
    );
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

fn route_for(routes: &[Route], destination: Ipv4Addr, prefix: u8) -> &Route {
    routes
        .iter()
        .find(|route| route.destination() == IpAddr::V4(destination) && route.prefix() == prefix)
        .expect("expected route to be present")
}
