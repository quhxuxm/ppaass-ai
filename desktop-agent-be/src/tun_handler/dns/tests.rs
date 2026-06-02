use super::*;

#[test]
fn parses_scutil_and_resolv_dns_addresses() {
    let output = r#"
resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 11 (en0)
resolver #2
nameserver 1.1.1.1
"#;

    assert_eq!(
        parse_dns_server_ips(output),
        vec![
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            IpAddr::V4("8.8.8.8".parse().unwrap()),
            IpAddr::V4("1.1.1.1".parse().unwrap()),
        ]
    );
    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            macos::parse_macos_dns_servers(output),
            vec![
                SystemDnsServer {
                    ip: IpAddr::V4("192.168.1.1".parse().unwrap()),
                    interface_name: Some("en0".to_string()),
                },
                SystemDnsServer {
                    ip: IpAddr::V4("8.8.8.8".parse().unwrap()),
                    interface_name: Some("en0".to_string()),
                },
                SystemDnsServer {
                    ip: IpAddr::V4("1.1.1.1".parse().unwrap()),
                    interface_name: None,
                },
            ]
        );
    }
}
