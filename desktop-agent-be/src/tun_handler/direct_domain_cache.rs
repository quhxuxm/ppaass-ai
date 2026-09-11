use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Stale grace period: expired entries remain usable this long to prevent route flip-flops.
const STALE_GRACE: Duration = Duration::from_secs(1800);
pub const MAX_CACHE_IPS: usize = 4096;
pub const MAX_DOMAINS_PER_IP: usize = 16;

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
    // TUN TCP/UDP route selection reads this for every new flow. Publish DNS
    // updates as immutable snapshots so that those lookups never take a map
    // shard lock or contend with DNS response processing.
    ip_to_domains: ArcSwap<HashMap<IpAddr, DomainCacheEntry>>,
}

impl DirectDomainCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            ip_to_domains: ArcSwap::from_pointee(HashMap::new()),
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
        let now = Instant::now();
        let expires_at = now + effective_ttl;
        let ips: Vec<_> = answers
            .iter()
            .filter_map(|answer| answer.parse::<IpAddr>().ok())
            .collect();
        if ips.is_empty() {
            return;
        }

        loop {
            let current = self.ip_to_domains.load_full();
            let mut updated = (*current).clone();
            for ip in &ips {
                let entry = updated.entry(*ip).or_insert_with(|| DomainCacheEntry {
                    domains: Vec::new(),
                    expires_at,
                });
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
            }
            trim_to_capacity(&mut updated);
            let previous = self
                .ip_to_domains
                .compare_and_swap(&current, Arc::new(updated));
            if Arc::ptr_eq(&*previous, &current) {
                return;
            }
        }
    }

    pub fn domains_for_ip(&self, ip: IpAddr) -> Vec<String> {
        let snapshot = self.ip_to_domains.load();
        let entry = match snapshot.get(&ip) {
            Some(entry) => entry,
            None => return Vec::new(),
        };
        let now = Instant::now();
        if now > entry.expires_at + STALE_GRACE {
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
        let snapshot = self.ip_to_domains.load();
        let entry = snapshot.get(&ip)?;
        let now = Instant::now();
        if now > entry.expires_at + STALE_GRACE {
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

    #[doc(hidden)]
    pub fn cached_ip_count(&self) -> usize {
        self.ip_to_domains.load().len()
    }
}

fn trim_to_capacity(entries: &mut HashMap<IpAddr, DomainCacheEntry>) {
    let overflow = entries.len().saturating_sub(MAX_CACHE_IPS);
    if overflow == 0 {
        return;
    }
    let mut by_expiry: Vec<_> = entries
        .iter()
        .map(|(ip, entry)| (*ip, entry.expires_at))
        .collect();
    by_expiry.sort_by_key(|(_, expires_at)| *expires_at);
    for (ip, _) in by_expiry.into_iter().take(overflow) {
        entries.remove(&ip);
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
