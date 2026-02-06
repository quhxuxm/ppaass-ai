use std::{fmt::Debug, time::Duration};

/// Configuration for a client connection
pub trait ClientConnectionConfig: Debug {
    /// Get a randomly selected remote address to connect to
    fn remote_addr(&self) -> String;

    /// Username for authentication
    fn username(&self) -> String;

    /// Private key PEM for encryption
    fn private_key_pem(&self) -> Result<String, String>;

    /// Timeout duration for connection operations (required)
    fn timeout_duration(&self) -> Duration;
}
