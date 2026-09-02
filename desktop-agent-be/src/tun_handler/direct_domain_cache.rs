use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::debug;

/// Stale grace period: expired entries remain usable this long to prevent route flip-flops.
const STALE_GRACE: Duration = Duration::from_secs(1800);

#[derive(Clone)]
struct DomainCacheEntry {
    domains: Vec<String>,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatch {
    Fresh(String),
    Stale(String),
}

impl DomainMatch {
    pub fn domain(&self) -> &str {
        match self {
            Self::Fresh(d) | Self::Stale(d) => d,
        }
    }

    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Stale(_))
    }

    pub fn into_domain(self) -> String {
        match self {
            Self::Fresh(d) | Self::Stale(d) => d,
        }
    }
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
        self.record_resolution_with_ttl(query, answers, None);
    }

    /// Record a DNS resolution with an optional per-record TTL from the DNS response.
    pub fn record_resolution_with_ttl(
        &self,
        query: &str,
        answers: &[String],
        dns_ttl: Option<u32>,
    ) {
        let domain = normalize_domain(query);
        if domain.is_empty() {
            return;
        }

        let effective_ttl = dns_ttl
            .map(|secs| Duration::from_secs(u64::from(secs)).min(Duration::from_secs(3600)))
            .unwrap_or(self.ttl);
        let expires_at = Instant::now() + effective_ttl;
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
        let now = Instant::now();
        if now > entry.expires_at + STALE_GRACE {
            drop(entry);
            self.ip_to_domains.remove(&ip);
            return Vec::new();
        }
        entry.domains.clone()
    }

    /// Find a domain for the given IP that satisfies `predicate`.
    /// Returns `Fresh` if within TTL, `Stale` if expired but within grace period.
    pub fn matching_domain_for_ip<F>(&self, ip: IpAddr, mut predicate: F) -> Option<DomainMatch>
    where
        F: FnMut(&str) -> bool,
    {
        let entry = self.ip_to_domains.get(&ip)?;
        let now = Instant::now();
        if now > entry.expires_at + STALE_GRACE {
            drop(entry);
            self.ip_to_domains.remove(&ip);
            return None;
        }
        let stale = now > entry.expires_at;
        let domain = entry
            .domains
            .iter()
            .find(|domain| predicate(domain.as_str()))
            .cloned()?;
        if stale {
            debug!("域名缓存 stale 命中 {ip} -> {domain}（过期但仍在宽限期内）");
        }
        Some(if stale {
            DomainMatch::Stale(domain)
        } else {
            DomainMatch::Fresh(domain)
        })
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
