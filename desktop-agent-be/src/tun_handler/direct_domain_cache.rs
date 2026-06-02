use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct DomainCacheEntry {
    domain: String,
    expires_at: Instant,
}

pub(super) struct DirectDomainCache {
    ttl: Duration,
    ip_to_domain: DashMap<IpAddr, DomainCacheEntry>,
}

impl DirectDomainCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domain: DashMap::new(),
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
                self.ip_to_domain.insert(
                    ip,
                    DomainCacheEntry {
                        domain: domain.clone(),
                        expires_at,
                    },
                );
            }
        }
    }

    pub(super) fn domain_for_ip(&self, ip: IpAddr) -> Option<String> {
        let entry = self.ip_to_domain.get(&ip)?;
        if entry.expires_at <= Instant::now() {
            drop(entry);
            self.ip_to_domain.remove(&ip);
            return None;
        }
        Some(entry.domain.clone())
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
