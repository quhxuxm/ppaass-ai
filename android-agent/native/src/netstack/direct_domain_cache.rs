use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct DomainCacheEntry {
    domains: Vec<String>,
    expires_at: Instant,
}

pub(super) struct DirectDomainCache {
    ttl: Duration,
    ip_to_domains: DashMap<IpAddr, DomainCacheEntry>,
}

impl DirectDomainCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domains: DashMap::new(),
        }
    }

    pub(super) fn record_resolution(&self, query: &str, answers: &[String]) {
        let domain = normalize_domain(query);
        if domain.is_empty() {
            return;
        }

        let expires_at = Instant::now() + self.ttl;
        for answer in answers {
            if let Ok(ip) = answer.parse::<IpAddr>() {
                if let Some(mut entry) = self.ip_to_domains.get_mut(&ip) {
                    if entry.expires_at <= Instant::now() {
                        entry.domains.clear();
                    }
                    if !entry.domains.iter().any(|existing| existing == &domain) {
                        entry.domains.push(domain.clone());
                    }
                    entry.expires_at = expires_at;
                } else {
                    self.ip_to_domains.insert(
                        ip,
                        DomainCacheEntry {
                            domains: vec![domain.clone()],
                            expires_at,
                        },
                    );
                }
            }
        }
    }

    #[cfg(test)]
    fn domains_for_ip(&self, ip: IpAddr) -> Vec<String> {
        let entry = match self.ip_to_domains.get(&ip) {
            Some(entry) => entry,
            None => return Vec::new(),
        };
        if entry.expires_at <= Instant::now() {
            drop(entry);
            self.ip_to_domains.remove(&ip);
            return Vec::new();
        }
        entry.domains.clone()
    }

    pub(super) fn matching_domain_for_ip<F>(&self, ip: IpAddr, mut predicate: F) -> Option<String>
    where
        F: FnMut(&str) -> bool,
    {
        let entry = match self.ip_to_domains.get(&ip) {
            Some(entry) => entry,
            None => return None,
        };
        if entry.expires_at <= Instant::now() {
            drop(entry);
            self.ip_to_domains.remove(&ip);
            return None;
        }
        entry
            .domains
            .iter()
            .find(|domain| predicate(domain.as_str()))
            .cloned()
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
