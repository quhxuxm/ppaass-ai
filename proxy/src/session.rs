use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

#[derive(Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub username: String,
    pub created_at: Instant,
    pub last_activity: Instant,
}

pub struct SessionManager {
    sessions: Arc<DashMap<String, SessionInfo>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn create_session(&self, username: String) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Instant::now();

        let session = SessionInfo {
            session_id: session_id.clone(),
            username,
            created_at: now,
            last_activity: now,
        };

        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn remove_session(&self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.iter().map(|e| e.value().clone()).collect()
    }

    pub fn cleanup_expired(&self, timeout_secs: u64) {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        self.sessions
            .retain(|_, session| session.last_activity.elapsed() < timeout);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
