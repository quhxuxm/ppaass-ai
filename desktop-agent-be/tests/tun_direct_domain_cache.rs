use desktop_agent_be::tun_handler::direct_domain_cache::DirectDomainCache;
use std::time::Duration;

#[test]
fn keeps_multiple_domains_for_shared_ip() {
    let cache = DirectDomainCache::new(Duration::from_secs(60));
    cache.record_resolution("www.youtube.com", &["142.250.1.1".to_string()]);
    cache.record_resolution("youtubei.googleapis.com", &["142.250.1.1".to_string()]);

    assert_eq!(
        cache.domains_for_ip("142.250.1.1".parse().unwrap()),
        vec![
            "www.youtube.com".to_string(),
            "youtubei.googleapis.com".to_string()
        ]
    );
}

#[test]
fn keeps_expired_domain_during_stale_grace_period() {
    let cache = DirectDomainCache::new(Duration::from_secs(60));
    cache.record_resolution_with_ttl(
        "teams.microsoft.com",
        &["203.0.113.10".to_string()],
        Some(0),
    );

    let domain_match = cache
        .matching_domain_for_ip("203.0.113.10".parse().unwrap(), |_| true)
        .expect("stale entry should remain available during grace period");
    assert!(domain_match.is_stale());
    assert_eq!(domain_match.domain(), "teams.microsoft.com");
}

#[test]
fn ignores_non_ip_answers() {
    let cache = DirectDomainCache::new(Duration::from_secs(60));
    cache.record_resolution(
        "www.youtube.com",
        &["rr1.googlevideo.com".to_string(), "142.250.1.1".to_string()],
    );

    assert_eq!(
        cache.domains_for_ip("142.250.1.1".parse().unwrap()),
        vec!["www.youtube.com".to_string()]
    );
}

#[test]
fn finds_matching_domain_for_ip() {
    let cache = DirectDomainCache::new(Duration::from_secs(60));
    cache.record_resolution("www.youtube.com", &["142.250.1.1".to_string()]);
    cache.record_resolution("youtubei.googleapis.com", &["142.250.1.1".to_string()]);

    assert_eq!(
        cache
            .matching_domain_for_ip("142.250.1.1".parse().unwrap(), |domain| {
                domain.ends_with("googleapis.com")
            })
            .map(|domain_match| domain_match.into_domain()),
        Some("youtubei.googleapis.com".to_string())
    );
    assert!(
        cache
            .matching_domain_for_ip("142.250.1.1".parse().unwrap(), |domain| {
                domain == "example.com"
            })
            .is_none()
    );
}
