use std::fmt::Debug;

/// Configuration for a client connection
pub trait ClientConnectionConfig: Debug {
    /// Remote address to connect to
    fn remote_addr(&self) -> String;

    /// Username for authentication
    fn username(&self) -> String;

    /// Private key PEM for encryption
    fn private_key_pem(&self) -> Result<String, String>;

    /// Optional timeout duration for connection operations
    fn timeout_duration(&self) -> Option<std::time::Duration> {
        None
    }
}
