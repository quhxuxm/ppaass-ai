mod android_log;
mod authentication;
mod config;
mod direct_access;
mod error;
mod fd_device;
pub mod http_proxy;
mod http_proxy_body;
mod http_proxy_clients;
mod http_proxy_io;
mod jni_api;
pub mod netstack;
#[doc(hidden)]
pub mod packet_capture;
mod socket_protector;
mod socks5_proxy;
mod tcp_relay;
mod traffic_stats;
pub mod yamux_session;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub use authentication::{
    AUTHENTICATION_UNCONFIRMED, AUTHENTICATION_USER_DISABLED, AUTHENTICATION_USER_EXPIRED,
    AUTHENTICATION_VERIFIED_ACTIVE, VerifiedAuthenticationState,
};
pub use config::{AndroidAgentConfig, AndroidTunConfig};
pub use direct_access::{DirectAccessChecker, DirectAccessConfig, DirectAccessMode};
pub use error::{AndroidAgentError, Result};
pub use http_proxy::run_android_http_proxy;
pub use http_proxy_clients::{http_proxy_clients_json, register_http_proxy_client};
#[doc(hidden)]
pub use jni_api::validate_key_pair;
pub use netstack::run_android_agent;
pub use tcp_relay::{TcpRelayOptions, TcpRelayStats, relay_tcp_bidirectional};
