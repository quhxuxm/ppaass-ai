//! Agent 到 proxy 的外层传输选择。

use serde::{Deserialize, Serialize};

/// Agent 与 proxy 之间承载 PPAASS 认证/数据帧的传输协议。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// QUIC 连接上的独立双向流。避免 TCP 队头阻塞，并可通过连接池分散拥塞窗口。
    #[default]
    Quic,
    /// 兼容旧版本 proxy 的 TCP/Yamux 传输。
    Tcp,
}

impl TransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
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
}
