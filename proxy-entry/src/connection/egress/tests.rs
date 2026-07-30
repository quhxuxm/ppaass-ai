use super::*;

#[test]
fn splits_domain_and_ipv6_targets_without_ambiguity() {
    assert_eq!(
        split_domain_target("example.test:443").unwrap(),
        ("example.test", 443)
    );
    assert_eq!(
        split_domain_target("::ffff:127.0.0.1:8787").unwrap(),
        ("::ffff:127.0.0.1", 8787)
    );
    assert_eq!(
        split_domain_target("[2001:db8::1]:8443").unwrap(),
        ("2001:db8::1", 8443)
    );
    assert_eq!(
        split_domain_target("not:an:ipv6:443").unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        split_domain_target("[example.test]:443")
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn configured_dns_keeps_bare_ipv6_domain_host_numeric() {
    let egress = EgressState::new(None, Some("127.0.0.1:53")).unwrap();
    assert_eq!(
        egress
            .resolve_target("::ffff:127.0.0.1:8787")
            .await
            .unwrap(),
        vec![SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), 8787)]
    );
}
