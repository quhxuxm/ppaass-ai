use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use super::{
    DecryptedUdpFragment, UDP_MAX_FRAGMENT_PLAINTEXT, UDP_MAX_FRAGMENTS, UDP_MAX_MESSAGE_SIZE,
    UdpSessionId, UdpTransportError, UdpTransportResult,
};

// These limits apply independently to every authenticated UDP session. One full
// protocol message is at most 70 KiB, so 1 MiB still permits roughly fourteen
// maximum-sized messages to be reassembled concurrently without allowing a
// single idle session to reserve several MiB indefinitely.
const DEFAULT_MAX_ENTRIES: usize = 64;
const DEFAULT_MAX_TOTAL_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    pub max_entries: usize,
    pub max_total_bytes: usize,
    pub timeout: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug)]
struct ReassemblyEntry {
    fragment_count: u16,
    total_len: u32,
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    received_bytes: usize,
    updated_at: Instant,
}

/// Bounded per-session fragment accumulator.
#[derive(Debug)]
pub struct FragmentReassembler {
    config: ReassemblyConfig,
    entries: HashMap<(UdpSessionId, u64), ReassemblyEntry>,
    total_bytes: usize,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::from_valid_config(ReassemblyConfig::default())
    }
}

impl FragmentReassembler {
    pub fn new(config: ReassemblyConfig) -> UdpTransportResult<Self> {
        if config.max_entries == 0 {
            return Err(UdpTransportError::ReassemblyLimit(
                "max_entries must be non-zero",
            ));
        }
        if config.max_total_bytes == 0 {
            return Err(UdpTransportError::ReassemblyLimit(
                "max_total_bytes must be non-zero",
            ));
        }
        if config.timeout.is_zero() {
            return Err(UdpTransportError::ReassemblyLimit(
                "timeout must be non-zero",
            ));
        }
        Ok(Self::from_valid_config(config))
    }

    fn from_valid_config(config: ReassemblyConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            total_bytes: 0,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn push(
        &mut self,
        fragment: DecryptedUdpFragment,
        now: Instant,
    ) -> UdpTransportResult<Option<Vec<u8>>> {
        validate_fragment(&fragment)?;

        let header = fragment.header;
        if header.fragment_count == 1 {
            if fragment.payload.len() != header.total_len as usize {
                return Err(UdpTransportError::InvalidHeader(
                    "single fragment length does not match total_len",
                ));
            }
            return Ok(Some(fragment.payload));
        }

        self.cleanup_expired(now);

        let key = (header.session_id, header.message_id);
        if !self.entries.contains_key(&key) {
            if fragment.payload.len() > self.config.max_total_bytes {
                return Err(UdpTransportError::ReassemblyLimit(
                    "current message exceeds maximum buffered fragment bytes",
                ));
            }
            if self.entries.len() >= self.config.max_entries {
                self.evict_oldest_except(None)?.ok_or(
                    UdpTransportError::InconsistentReassemblyState(
                        "a full reassembly table has no entry to evict",
                    ),
                )?;
            }
            self.entries.insert(
                key,
                ReassemblyEntry {
                    fragment_count: header.fragment_count,
                    total_len: header.total_len,
                    fragments: (0..usize::from(header.fragment_count))
                        .map(|_| None)
                        .collect(),
                    received_count: 0,
                    received_bytes: 0,
                    updated_at: now,
                },
            );
        }

        let index = usize::from(header.fragment_index);
        let entry_bytes = {
            let entry =
                self.entries
                    .get(&key)
                    .ok_or(UdpTransportError::InconsistentReassemblyState(
                        "reassembly entry is missing after insertion",
                    ))?;
            if entry.fragment_count != header.fragment_count || entry.total_len != header.total_len
            {
                return Err(UdpTransportError::ConflictingFragment);
            }
            if let Some(existing) = &entry.fragments[index] {
                return if existing == &fragment.payload {
                    Ok(None)
                } else {
                    Err(UdpTransportError::ConflictingFragment)
                };
            }

            let entry_bytes = entry
                .received_bytes
                .checked_add(fragment.payload.len())
                .ok_or(UdpTransportError::InvalidHeader(
                    "fragment byte counter overflow",
                ))?;
            if entry_bytes > entry.total_len as usize {
                return Err(UdpTransportError::InvalidHeader(
                    "fragment bytes exceed declared total_len",
                ));
            }
            if entry_bytes > self.config.max_total_bytes {
                return Err(UdpTransportError::ReassemblyLimit(
                    "current message exceeds maximum buffered fragment bytes",
                ));
            }
            entry_bytes
        };

        loop {
            let new_total = self.total_bytes.checked_add(fragment.payload.len()).ok_or(
                UdpTransportError::ReassemblyLimit("buffer byte counter overflow"),
            )?;
            if new_total <= self.config.max_total_bytes {
                break;
            }
            self.evict_oldest_except(Some(key))?
                .ok_or(UdpTransportError::ReassemblyLimit(
                    "maximum buffered fragment bytes reached",
                ))?;
        }

        let new_total = self.total_bytes.checked_add(fragment.payload.len()).ok_or(
            UdpTransportError::ReassemblyLimit("buffer byte counter overflow"),
        )?;
        let entry =
            self.entries
                .get_mut(&key)
                .ok_or(UdpTransportError::InconsistentReassemblyState(
                    "current reassembly entry was evicted",
                ))?;

        entry.fragments[index] = Some(fragment.payload);
        entry.received_count += 1;
        entry.received_bytes = entry_bytes;
        entry.updated_at = now;
        self.total_bytes = new_total;

        if entry.received_count != usize::from(entry.fragment_count) {
            return Ok(None);
        }

        let entry =
            self.entries
                .remove(&key)
                .ok_or(UdpTransportError::InconsistentReassemblyState(
                    "complete reassembly entry is missing",
                ))?;
        self.total_bytes -= entry.received_bytes;
        if entry.received_bytes != entry.total_len as usize {
            return Err(UdpTransportError::InvalidHeader(
                "reassembled length does not match total_len",
            ));
        }
        let mut message = Vec::with_capacity(entry.received_bytes);
        for fragment in entry.fragments {
            let fragment =
                fragment
                    .as_deref()
                    .ok_or(UdpTransportError::InconsistentReassemblyState(
                        "completed message contains a missing fragment",
                    ))?;
            message.extend_from_slice(fragment);
        }
        Ok(Some(message))
    }

    fn evict_oldest_except(
        &mut self,
        except: Option<(UdpSessionId, u64)>,
    ) -> UdpTransportResult<Option<(UdpSessionId, u64)>> {
        let Some(oldest) = self
            .entries
            .iter()
            .filter(|(key, _)| except.as_ref() != Some(*key))
            .min_by_key(|(_, entry)| entry.updated_at)
            .map(|(key, _)| *key)
        else {
            return Ok(None);
        };
        let removed =
            self.entries
                .remove(&oldest)
                .ok_or(UdpTransportError::InconsistentReassemblyState(
                    "selected reassembly entry is missing",
                ))?;
        self.total_bytes -= removed.received_bytes;
        Ok(Some(oldest))
    }

    pub fn cleanup_expired(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let timeout = self.config.timeout;
        let mut removed_bytes = 0;
        self.entries.retain(|_, entry| {
            let age = now
                .checked_duration_since(entry.updated_at)
                .unwrap_or_default();
            let keep = age < timeout;
            if !keep {
                removed_bytes += entry.received_bytes;
            }
            keep
        });
        self.total_bytes -= removed_bytes;
        before - self.entries.len()
    }
}

fn validate_fragment(fragment: &DecryptedUdpFragment) -> UdpTransportResult<()> {
    fragment.header.validate()?;
    if fragment.payload.len() > UDP_MAX_FRAGMENT_PLAINTEXT {
        return Err(UdpTransportError::InvalidHeader(
            "fragment plaintext exceeds datagram capacity",
        ));
    }
    if fragment.header.total_len as usize > UDP_MAX_MESSAGE_SIZE {
        return Err(UdpTransportError::MessageTooLarge(
            fragment.header.total_len as usize,
        ));
    }
    if fragment.payload.len() > fragment.header.total_len as usize {
        return Err(UdpTransportError::InvalidHeader(
            "fragment bytes exceed declared total_len",
        ));
    }
    if usize::from(fragment.header.fragment_count) > UDP_MAX_FRAGMENTS {
        return Err(UdpTransportError::TooManyFragments(usize::from(
            fragment.header.fragment_count,
        )));
    }
    if fragment.header.total_len != 0 && fragment.payload.is_empty() {
        return Err(UdpTransportError::InvalidHeader(
            "non-empty messages cannot contain empty fragments",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bound_each_session_without_reducing_message_limit() {
        let config = ReassemblyConfig::default();

        assert_eq!(config.max_entries, 64);
        assert_eq!(config.max_total_bytes, 1024 * 1024);
        assert_eq!(config.timeout, Duration::from_secs(1));
        assert!(config.max_total_bytes >= UDP_MAX_MESSAGE_SIZE);
    }
}
