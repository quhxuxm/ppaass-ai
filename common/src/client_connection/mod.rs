//! agent 与 proxy 共用的统一客户端连接模块

pub mod authenticated;
pub mod client;
pub mod config;
pub mod stream;

// 重新导出公共项
pub use authenticated::AuthenticatedConnection;
pub use client::ClientConnection;
pub use config::{BindInterface, ClientConnectionConfig};
pub use stream::ClientStream;
