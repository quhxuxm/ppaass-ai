#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEventRecord {
    pub revision: u64,
    pub kind: String,
    pub account_id: Option<String>,
}
