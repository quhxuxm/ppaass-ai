#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAgentWebSessionHandoff {
    pub code_hash: String,
    pub account_id: String,
    pub account_auth_version: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWebSessionHandoffCreate {
    Created,
    Capacity,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentWebSessionHandoffConsume {
    Claimed {
        account_id: String,
        account_auth_version: i64,
    },
    Expired,
    NotFound,
}
