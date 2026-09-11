//! agent 连接 proxy-entry 时使用的 PPAASS 子流握手逻辑。
//!
//! 外层 raw TCP 只承载 Yamux session；每个 Yamux 子 stream 内执行：
//! 发送 AuthConnect（认证与加密目标意图）后启用 AES；Proxy 随即返回
//! `ConnectResponse` 并开始数据中继。

mod handshake;
mod status;
mod tcp;

pub use handshake::AuthenticatedConnection;
pub use status::{
    AuthenticationFailure, VerifiedAuthAttempt, VerifiedProxyAuthStatus, auth_failure_code,
    subscribe_verified_proxy_auth_statuses,
};
pub(super) use tcp::connect_tcp_stream;
