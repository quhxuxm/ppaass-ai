use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_CACHE_IPS: usize = 4096;
const MAX_DOMAINS_PER_IP: usize = 16;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct DomainCacheEntry {
    domains: Vec<String>,
    expires_at: Instant,
}

pub(super) struct DirectDomainCache {
    ttl: Duration,
    ip_to_domains: DashMap<IpAddr, DomainCacheEntry>,
    last_cleanup: Mutex<Instant>,
}

impl DirectDomainCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domains: DashMap::new(),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    pub(super) fn record_resolution(&self, query: &str, answers: &[String]) {
        let domain = normalize_domain(query);
        if domain.is_empty() {
            return;
        }

        let now = Instant::now();
        self.cleanup_if_due(now);
        let expires_at = now + self.ttl;
        let mut recorded = false;
        for answer in answers {
            if let Ok(ip) = answer.parse::<IpAddr>() {
                if let Some(mut entry) = self.ip_to_domains.get_mut(&ip) {
                    if entry.expires_at <= now {
                        entry.domains.clear();
                    }
                    if !entry.domains.iter().any(|existing| existing == &domain) {
                        if entry.domains.len() >= MAX_DOMAINS_PER_IP {
                            entry.domains.remove(0);
                        }
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
                recorded = true;
            }
        }
        if recorded && self.ip_to_domains.len() > MAX_CACHE_IPS {
            self.enforce_capacity();
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
        let entry = self.ip_to_domains.get(&ip)?;
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

    fn cleanup_if_due(&self, now: Instant) {
        let Ok(mut last_cleanup) = self.last_cleanup.try_lock() else {
            return;
        };
        if now.duration_since(*last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        *last_cleanup = now;
        drop(last_cleanup);

        self.remove_expired(now);
        if self.ip_to_domains.len() > MAX_CACHE_IPS {
            self.enforce_capacity();
        }
    }

    fn remove_expired(&self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .ip_to_domains
            .iter()
            .filter_map(|entry| (entry.expires_at <= now).then_some(*entry.key()))
            .collect();
        for ip in expired {
            self.ip_to_domains.remove(&ip);
        }
    }

    fn enforce_capacity(&self) {
        let len = self.ip_to_domains.len();
        if len <= MAX_CACHE_IPS {
            return;
        }

        let mut entries: Vec<(IpAddr, Instant)> = self
            .ip_to_domains
            .iter()
            .map(|entry| (*entry.key(), entry.expires_at))
            .collect();
        entries.sort_by_key(|(_, expires_at)| *expires_at);

        for (ip, _) in entries.into_iter().take(len - MAX_CACHE_IPS) {
            self.ip_to_domains.remove(&ip);
        }
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

    #[test]
    fn caps_domains_per_ip() {
        let cache = DirectDomainCache::new(Duration::from_secs(60));
        for index in 0..(MAX_DOMAINS_PER_IP + 1) {
            cache.record_resolution(
                &format!("d{index}.example.com"),
                &["142.250.1.1".to_string()],
            );
        }

        let domains = cache.domains_for_ip("142.250.1.1".parse().unwrap());
        assert_eq!(domains.len(), MAX_DOMAINS_PER_IP);
        assert!(!domains.contains(&"d0.example.com".to_string()));
        assert!(domains.contains(&format!("d{MAX_DOMAINS_PER_IP}.example.com")));
    }

    #[test]
    fn caps_total_cached_ips() {
        let cache = DirectDomainCache::new(Duration::from_secs(60));
        for index in 0..(MAX_CACHE_IPS + 1) {
            cache.record_resolution(
                &format!("d{index}.example.com"),
                &[format!(
                    "10.{}.{}.{}",
                    (index >> 16) & 255,
                    (index >> 8) & 255,
                    index & 255
                )],
            );
        }

        assert!(cache.ip_to_domains.len() <= MAX_CACHE_IPS);
    }
}
