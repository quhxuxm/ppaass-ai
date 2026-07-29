use super::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct DnsCacheKey {
    query: String,
    record_type: String,
}

pub(super) struct CachedDnsResponse {
    packet: Vec<u8>,
    expires_at: Instant,
}

#[derive(Default)]
pub(super) struct DnsResponseCache {
    entries: HashMap<DnsCacheKey, CachedDnsResponse>,
}

impl DnsResponseCache {
    pub(super) fn get(
        &mut self,
        query: &str,
        record_type: &str,
        request_id: u16,
    ) -> Option<Vec<u8>> {
        self.cleanup_expired();
        let key = dns_cache_key(query, record_type);
        let entry = self.entries.get(&key)?;
        if entry.expires_at <= Instant::now() {
            self.entries.remove(&key);
            return None;
        }

        let mut packet = entry.packet.clone();
        write_dns_id(&mut packet, request_id);
        Some(packet)
    }

    pub(super) fn insert(
        &mut self,
        query: &str,
        record_type: &str,
        summary: &DnsResponseSummary,
        response: &[u8],
    ) {
        if summary.status != "NOERROR" || summary.answers.is_empty() {
            return;
        }
        let Some(ttl_secs) = summary.min_ttl else {
            return;
        };
        if ttl_secs == 0 {
            return;
        }

        self.cleanup_expired();
        if self.entries.len() >= DNS_RESPONSE_CACHE_MAX_ENTRIES {
            self.evict_one();
        }

        let mut packet = response.to_vec();
        // 缓存完整 DNS 响应；命中时再替换成当前请求的 transaction id。
        write_dns_id(&mut packet, 0);
        self.entries.insert(
            dns_cache_key(query, record_type),
            CachedDnsResponse {
                packet,
                expires_at: Instant::now()
                    + Duration::from_secs(u64::from(ttl_secs)).min(DNS_RESPONSE_CACHE_MAX_TTL),
            },
        );
    }

    pub(super) fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    pub(super) fn evict_one(&mut self) {
        if let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&key);
        }
    }
}

pub(super) fn dns_cache_key(query: &str, record_type: &str) -> DnsCacheKey {
    DnsCacheKey {
        query: query.trim().trim_end_matches('.').to_ascii_lowercase(),
        record_type: record_type.to_ascii_uppercase(),
    }
}
