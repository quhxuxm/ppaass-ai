mod proxy_error;

pub use proxy_error::ProxyError;
pub type Result<T> = std::result::Result<T, ProxyError>;
