use super::UserRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEventRecord {
    pub revision: u64,
    pub kind: String,
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthorizationSnapshotQuery {
    pub after_username: Option<String>,
    pub expected_revision: Option<u64>,
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthorizationSnapshotPage {
    pub revision: u64,
    pub users: Vec<UserRecord>,
    pub next_cursor: Option<String>,
}
