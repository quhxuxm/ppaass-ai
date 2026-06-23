//! QUIC/UDP443 的共享策略与轻量观测。
//!
//! 当前项目不内置完整 QUIC 协议栈，而是把浏览器、系统或 App 发出的
//! UDP/443 数据报按普通 UDP relay 转发。这里集中定义“遇到 UDP/443 时
//! 应该放行、只允许直连，还是全部阻断”的策略，避免 desktop/Android
//! 两端各自维护一套容易漂移的判断。

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// TUN 模式下 UDP/443 的处理策略。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicPolicy {
    /// 默认策略：UDP/443 与普通 UDP 一样按 direct_access 决定直连或代理。
    #[default]
    Allow,
    /// 兼容旧 `block_quic = true` 的语义：命中直连规则的 QUIC 继续直连，
    /// 未命中直连规则的 UDP/443 会被丢弃，促使应用回退到 TCP/TLS。
    #[serde(alias = "block_proxied")]
    DirectIfRuleMatch,
    /// 强制阻断所有 UDP/443，不区分直连或代理路径。
    Block,
}

impl QuicPolicy {
    /// 根据当前目标是否命中直连规则，判断该 UDP/443 datagram 是否应该丢弃。
    pub fn should_block_udp443(self, direct_match: bool) -> bool {
        match self {
            Self::Allow => false,
            Self::DirectIfRuleMatch => !direct_match,
            Self::Block => true,
        }
    }

    /// 面向日志的中文说明，启动时打印一次即可，不参与协议逻辑。
    pub fn description_zh(self) -> &'static str {
        match self {
            Self::Allow => "允许 UDP/443 QUIC 按 direct_access 走直连或 UDP relay",
            Self::DirectIfRuleMatch => "仅允许命中直连规则的 UDP/443 QUIC，其他 QUIC 将被阻断",
            Self::Block => "阻断全部 UDP/443 QUIC，促使应用回退 TCP/TLS",
        }
    }
}

/// UDP/443 的低成本累计计数器。
///
/// 计数器只在 TUN 分流点按包递增，不做高频日志；调用方周期性 `snapshot_and_reset`
/// 后输出一行汇总即可，避免 QUIC 高频小包把日志系统打满。
#[derive(Debug, Default)]
pub struct QuicUdpStats {
    observed: AtomicU64,
    direct: AtomicU64,
    proxied: AtomicU64,
    blocked: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicUdpStatsSnapshot {
    pub observed: u64,
    pub direct: u64,
    pub proxied: u64,
    pub blocked: u64,
}

impl QuicUdpStats {
    pub fn record_direct(&self) {
        self.observed.fetch_add(1, Ordering::Relaxed);
        self.direct.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_proxied(&self) {
        self.observed.fetch_add(1, Ordering::Relaxed);
        self.proxied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.observed.fetch_add(1, Ordering::Relaxed);
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot_and_reset(&self) -> QuicUdpStatsSnapshot {
        QuicUdpStatsSnapshot {
            observed: self.observed.swap(0, Ordering::Relaxed),
            direct: self.direct.swap(0, Ordering::Relaxed),
            proxied: self.proxied.swap(0, Ordering::Relaxed),
            blocked: self.blocked.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_policy_blocks_expected_routes() {
        assert!(!QuicPolicy::Allow.should_block_udp443(false));
        assert!(!QuicPolicy::DirectIfRuleMatch.should_block_udp443(true));
        assert!(QuicPolicy::DirectIfRuleMatch.should_block_udp443(false));
        assert!(QuicPolicy::Block.should_block_udp443(true));
        assert!(QuicPolicy::Block.should_block_udp443(false));
    }

    #[test]
    fn quic_policy_uses_snake_case_config_values() {
        let policy: QuicPolicy = toml::from_str("value = \"direct_if_rule_match\"")
            .map(|wrapper: PolicyWrapper| wrapper.value)
            .unwrap();

        assert_eq!(policy, QuicPolicy::DirectIfRuleMatch);
    }

    #[test]
    fn quic_stats_snapshot_resets_counters() {
        let stats = QuicUdpStats::default();
        stats.record_direct();
        stats.record_proxied();
        stats.record_blocked();

        assert_eq!(
            stats.snapshot_and_reset(),
            QuicUdpStatsSnapshot {
                observed: 3,
                direct: 1,
                proxied: 1,
                blocked: 1,
            }
        );
        assert_eq!(stats.snapshot_and_reset(), QuicUdpStatsSnapshot::default());
    }

    #[derive(Deserialize)]
    struct PolicyWrapper {
        value: QuicPolicy,
    }
}
