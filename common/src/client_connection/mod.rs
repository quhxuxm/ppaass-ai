//! agent 与 proxy 共用的统一客户端连接模块

pub mod authenticated;
pub mod config;
pub mod quic;
pub mod socket_bind;
pub mod stream;
pub mod yamux;

// 重新导出公共项
pub use authenticated::AuthenticatedConnection;
pub use config::{BindInterface, ClientConnectionConfig};
pub use quic::{PPAASS_QUIC_ALPN, QuicBiStream, QuicClientConnection};
pub use socket_bind::bind_socket_to_interface;
pub use stream::ClientStream;
pub use yamux::{
    YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE, YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE,
    YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE, YamuxClientConnection, YamuxClientStream,
};
