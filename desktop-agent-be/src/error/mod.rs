mod agent_error;

pub use agent_error::AgentError;
pub type Result<T> = std::result::Result<T, AgentError>;
