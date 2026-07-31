//! Agent 到 proxy 的 UDP 外层传输选择。TCP 目标始终使用 direct framed TCP。

use protocol::TransportProtocol;
use serde::{Deserialize, Serialize};

/// Agent 与 proxy 之间承载 UDP 目标 PPAASS 帧的外层传输模式。
///
/// 这是一次不兼容的协议切换：只接受 `auto`/`udp`/`tcp`，旧 `quic` 值会直接
/// 反序列化失败，避免把 QUIC 配置静默解释成语义不同的原生 UDP。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// 自动模式：优先使用原生加密 UDP；原生 UDP 控制传输超时后，由 agent
    /// 将对应的 UDP session slot 在当前进程生命周期内切换为 TCP/Yamux。
    Auto,
    /// 混合模式：TCP 目标继续使用 direct framed TCP；只有 UDP 目标使用
    /// PPAASS 原生加密 UDP 会话。
    #[default]
    Udp,
    /// 全 TCP 模式：TCP 目标使用 direct framed TCP，UDP relay 使用 TCP/Yamux。
    Tcp,
}

impl TransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// 判断某类目标流是否应该使用原生 UDP 外层传输。
    ///
    /// TCP 目标无条件返回 false，确保 HTTP、SOCKS CONNECT 与 TUN TCP 始终
    /// 沿用 direct framed TCP；配置值 `udp` 只控制 UDP 目标流。
    pub fn uses_native_udp_for(self, transport: TransportProtocol) -> bool {
        matches!(
            (self, transport),
            (Self::Auto | Self::Udp, TransportProtocol::Udp)
        )
    }

    pub fn automatically_falls_back_to_tcp(self) -> bool {
        matches!(self, Self::Auto)
    }
}
