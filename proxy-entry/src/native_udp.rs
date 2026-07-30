//! PPAASS 原生加密 UDP 入站。
//!
//! listener 只负责按 `session_id` 分发数据报和建立已认证会话。每个会话
//! 独占协议层 `UdpSessionCodec` 与重放窗口，再按外层 `flow_id` 将 UDP 目标
//! 分发到独立 worker。任何队列拥塞都以丢弃单个 UDP 包处理，不引入重传或有序语义。

mod auth;
mod channel;
mod listener;
mod session;

pub(crate) use listener::run_listener;

use protocol::udp_transport::UdpSessionId;

fn session_label(session_id: &UdpSessionId) -> String {
    hex::encode(&session_id[..6])
}
