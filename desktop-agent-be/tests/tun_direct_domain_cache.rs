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
            .as_deref(),
        Some("youtubei.googleapis.com")
    );
    assert!(
        cache
            .matching_domain_for_ip("142.250.1.1".parse().unwrap(), |domain| {
                domain == "example.com"
            })
            .is_none()
    );
}
