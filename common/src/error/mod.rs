mod common_error;

pub use common_error::CommonError;
pub type Result<T> = std::result::Result<T, CommonError>;
