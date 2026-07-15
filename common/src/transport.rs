//! Agent 到 proxy 的 UDP 外层传输选择。TCP 目标始终使用 direct framed TCP。

use protocol::TransportProtocol;
use serde::{Deserialize, Serialize};

/// Agent 与 proxy 之间承载 UDP 目标 PPAASS 帧的外层传输模式。
///
/// 配置字段仍叫 `transport_mode` 并保留 `quic`/`tcp` 值，以兼容已有配置。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// 混合模式：TCP 目标继续使用 direct framed TCP；只有 UDP 目标使用
    /// QUIC 连接上的独立双向流与连接池。
    #[default]
    Quic,
    /// 全 TCP 模式：TCP 目标使用 direct framed TCP，UDP relay 使用 TCP/Yamux。
    Tcp,
}

impl TransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
    }

    /// 判断某类目标流是否应该使用 QUIC 外层传输。
    ///
    /// TCP 目标无条件返回 false，确保 HTTP、SOCKS CONNECT 与 TUN TCP 始终
    /// 沿用 direct framed TCP；配置值 `quic` 只控制 UDP 目标流。
    pub fn uses_quic_for(self, transport: TransportProtocol) -> bool {
        matches!((self, transport), (Self::Quic, TransportProtocol::Udp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_quic_and_parses_tcp() {
        assert_eq!(TransportMode::default(), TransportMode::Quic);
        #[derive(Deserialize)]
        struct Wrapper {
            mode: TransportMode,
        }
        assert_eq!(
            toml::from_str::<Wrapper>("mode = \"tcp\"").unwrap().mode,
            TransportMode::Tcp
        );
    }

    #[test]
    fn quic_mode_is_hybrid_and_never_routes_tcp_over_quic() {
        assert!(!TransportMode::Quic.uses_quic_for(TransportProtocol::Tcp));
        assert!(TransportMode::Quic.uses_quic_for(TransportProtocol::Udp));
        assert!(!TransportMode::Tcp.uses_quic_for(TransportProtocol::Tcp));
        assert!(!TransportMode::Tcp.uses_quic_for(TransportProtocol::Udp));
    }
}
