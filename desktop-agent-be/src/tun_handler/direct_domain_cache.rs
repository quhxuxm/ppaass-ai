use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct DomainCacheEntry {
    domains: Vec<String>,
    expires_at: Instant,
}

pub struct DirectDomainCache {
    ttl: Duration,
    ip_to_domains: DashMap<IpAddr, DomainCacheEntry>,
}

impl DirectDomainCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domains: DashMap::new(),
        }
    }

    pub fn record_resolution(&self, query: &str, answers: &[String]) {
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

    pub fn domains_for_ip(&self, ip: IpAddr) -> Vec<String> {
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

    pub fn matching_domain_for_ip<F>(&self, ip: IpAddr, mut predicate: F) -> Option<String>
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
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
