//! agent/proxy 级联场景共用的 PPAASS 子流握手逻辑。
//!
//! 外层 raw TCP 只承载 Yamux session；每个 Yamux 子 stream 内执行：
//! 发送 Auth -> 收到 AuthResponse 后启用 AES -> 发送 ConnectRequest ->
//! 返回 `ClientStream` 做数据中继。

mod handshake;
mod status;
mod tcp;

pub use handshake::AuthenticatedConnection;
#[cfg(test)]
use status::VerifiedAuthAttempt;
pub use status::{
    AuthenticationFailure, VerifiedProxyAuthStatus, auth_failure_code,
    subscribe_verified_proxy_auth_statuses,
};
pub(super) use tcp::connect_tcp_stream;

#[cfg(test)]
mod tests;
