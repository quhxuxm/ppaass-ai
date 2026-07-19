use super::UDP_REPLAY_WINDOW_SIZE;

const WORD_BITS: usize = u64::BITS as usize;
const WORD_COUNT: usize = UDP_REPLAY_WINDOW_SIZE / WORD_BITS;

const _: () = assert!(UDP_REPLAY_WINDOW_SIZE >= 4096);
const _: () = assert!(UDP_REPLAY_WINDOW_SIZE.is_multiple_of(WORD_BITS));

/// Sliding replay window. `may_accept` is side-effect free; callers must call
/// `commit` only after authenticating the packet.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: [u64; WORD_COUNT],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: [0; WORD_COUNT],
        }
    }

    pub fn highest_seen(&self) -> Option<u64> {
        self.highest
    }

    pub fn may_accept(&self, seq: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if seq > highest {
            return true;
        }

        let distance = highest - seq;
        if distance >= UDP_REPLAY_WINDOW_SIZE as u64 {
            return false;
        }
        !self.bit_is_set(distance as usize)
    }

    /// Commit an authenticated sequence number. Returns false if it has become
    /// duplicate or too old since `may_accept` was called.
    pub fn commit(&mut self, seq: u64) -> bool {
        if !self.may_accept(seq) {
            return false;
        }

        match self.highest {
            None => {
                self.highest = Some(seq);
                self.set_bit(0);
            }
            Some(highest) if seq > highest => {
                let advance = seq - highest;
                if advance >= UDP_REPLAY_WINDOW_SIZE as u64 {
                    self.seen.fill(0);
                } else {
                    self.shift_older(advance as usize);
                }
                self.highest = Some(seq);
                self.set_bit(0);
            }
            Some(highest) => self.set_bit((highest - seq) as usize),
        }
        true
    }

    fn bit_is_set(&self, distance: usize) -> bool {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;
        self.seen[word] & (1_u64 << bit) != 0
    }

    fn set_bit(&mut self, distance: usize) {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;
        self.seen[word] |= 1_u64 << bit;
    }

    fn shift_older(&mut self, distance: usize) {
        if distance >= UDP_REPLAY_WINDOW_SIZE {
            self.seen.fill(0);
            return;
        }

        let word_shift = distance / WORD_BITS;
        let bit_shift = distance % WORD_BITS;
        let mut shifted = [0_u64; WORD_COUNT];
        for (source, value) in self.seen.iter().copied().enumerate() {
            let destination = source + word_shift;
            if destination >= WORD_COUNT {
                break;
            }
            shifted[destination] |= value << bit_shift;
            if bit_shift != 0 && destination + 1 < WORD_COUNT {
                shifted[destination + 1] |= value >> (WORD_BITS - bit_shift);
            }
        }
        self.seen = shifted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_out_of_order_and_rejects_duplicate_and_too_old() {
        let mut replay = ReplayWindow::new();
        assert!(replay.commit(10_000));
        assert!(replay.commit(9_998));
        assert!(replay.commit(9_999));
        assert!(!replay.may_accept(9_999));
        assert!(!replay.commit(9_999));

        assert!(replay.commit(10_000 - (UDP_REPLAY_WINDOW_SIZE as u64 - 1)));
        assert!(!replay.may_accept(10_000 - UDP_REPLAY_WINDOW_SIZE as u64));
    }

    #[test]
    fn large_forward_jump_clears_old_bits() {
        let mut replay = ReplayWindow::new();
        assert!(replay.commit(1));
        assert!(replay.commit(10_000));
        assert!(!replay.may_accept(1));
        assert!(replay.may_accept(9_999));

        // Keep u64 distance checks correct on 32-bit Android targets too.
        assert!(replay.commit(u64::MAX));
        assert!(!replay.may_accept(0));
    }
}
