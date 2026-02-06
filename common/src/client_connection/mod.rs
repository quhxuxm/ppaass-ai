//! Unified client connection module for both agent and proxy

pub mod authenticated;
pub mod client;
pub mod config;
pub mod stream;

// Re-export public items
pub use authenticated::AuthenticatedConnection;
pub use client::ClientConnection;
pub use config::ClientConnectionConfig;
pub use stream::ClientStream;
