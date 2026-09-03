use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub const MAX_CACHE_IPS: usize = 4096;
pub const MAX_DOMAINS_PER_IP: usize = 16;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
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
    cleanup_epoch: Instant,
    last_cleanup_millis: AtomicU64,
}

impl DirectDomainCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domains: DashMap::new(),
            cleanup_epoch: Instant::now(),
            last_cleanup_millis: AtomicU64::new(0),
        }
    }

    pub fn record_resolution(&self, query: &str, answers: &[String]) {
        self.record_resolution_with_ttl(query, answers, None);
    }

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

        let now = Instant::now();
        self.cleanup_if_due(now);
        let effective_ttl = dns_ttl
            .map(|secs| Duration::from_secs(u64::from(secs)).min(Duration::from_secs(3600)))
            .unwrap_or(self.ttl);
        let expires_at = now + effective_ttl;
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

    #[doc(hidden)]
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
        Some(if stale {
            DomainMatch::Stale(domain)
        } else {
            DomainMatch::Fresh(domain)
        })
    }

    pub fn cached_ip_count(&self) -> usize {
        self.ip_to_domains.len()
    }

    fn cleanup_if_due(&self, now: Instant) {
        let elapsed_millis = now
            .duration_since(self.cleanup_epoch)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let last_cleanup_millis = self.last_cleanup_millis.load(Ordering::Relaxed);
        if elapsed_millis.saturating_sub(last_cleanup_millis) < CLEANUP_INTERVAL.as_millis() as u64
        {
            return;
        }
        if self
            .last_cleanup_millis
            .compare_exchange(
                last_cleanup_millis,
                elapsed_millis,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        self.remove_expired(now);
        if self.ip_to_domains.len() > MAX_CACHE_IPS {
            self.enforce_capacity();
        }
    }

    fn remove_expired(&self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .ip_to_domains
            .iter()
            .filter_map(|entry| (now > entry.expires_at + STALE_GRACE).then_some(*entry.key()))
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
