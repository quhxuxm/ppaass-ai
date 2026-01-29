use crate::config::ProxyConfig;
use common::{
    bandwidth::{BandwidthLimiter, BandwidthTracker},
    config::UserConfig,
    crypto::hash_password,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::Serialize;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct UserInfo {
    pub config: UserConfig,
    pub bandwidth_limiter: Option<BandwidthLimiter>,
    pub bandwidth_tracker: BandwidthTracker,
    pub active_connections: Arc<RwLock<usize>>,
}

pub struct UserManager {
    config: Arc<ProxyConfig>,
    users: Arc<DashMap<String, UserInfo>>,
}

impl UserManager {
    pub fn new(config: Arc<ProxyConfig>) -> Self {
        let users = Arc::new(DashMap::new());

        // Load users from config
        for (username, user_config) in &config.users {
            let bandwidth_limiter = user_config
                .bandwidth_limit
                .map(|limit| BandwidthLimiter::new(limit));

            let bandwidth_tracker = BandwidthTracker::new(Duration::from_secs(60));

            users.insert(
                username.clone(),
                UserInfo {
                    config: user_config.clone(),
                    bandwidth_limiter,
                    bandwidth_tracker,
                    active_connections: Arc::new(RwLock::new(0)),
                },
            );
        }

        Self { config, users }
    }

    pub fn authenticate(&self, username: &str, password_hash: &str) -> bool {
        if let Some(user) = self.users.get(username) {
            let expected_hash = hash_password(&user.config.password);
            expected_hash == password_hash
        } else {
            false
        }
    }

    pub fn add_user(&self, username: String, user_config: UserConfig) -> bool {
        let bandwidth_limiter = user_config
            .bandwidth_limit
            .map(|limit| BandwidthLimiter::new(limit));

        let bandwidth_tracker = BandwidthTracker::new(Duration::from_secs(60));

        self.users
            .insert(
                username,
                UserInfo {
                    config: user_config,
                    bandwidth_limiter,
                    bandwidth_tracker,
                    active_connections: Arc::new(RwLock::new(0)),
                },
            )
            .is_none()
    }

    pub fn remove_user(&self, username: &str) -> bool {
        self.users.remove(username).is_some()
    }

    pub fn update_bandwidth_limit(&self, username: &str, limit: Option<u64>) -> bool {
        if let Some(mut user) = self.users.get_mut(username) {
            if let Some(limit) = limit {
                if let Some(ref limiter) = user.bandwidth_limiter {
                    limiter.set_limit(limit);
                } else {
                    user.bandwidth_limiter = Some(BandwidthLimiter::new(limit));
                }
            } else {
                user.bandwidth_limiter = None;
            }
            user.config.bandwidth_limit = limit;
            true
        } else {
            false
        }
    }

    pub fn list_users(&self) -> Vec<String> {
        self.users.iter().map(|e| e.key().clone()).collect()
    }

    pub fn get_user_stats(&self, username: &str) -> Option<UserStats> {
        self.users.get(username).map(|user| UserStats {
            username: username.to_string(),
            active_connections: *user.active_connections.read(),
            total_bytes: user.bandwidth_tracker.total_bytes(),
            current_bandwidth: user.bandwidth_tracker.current_bandwidth(),
            bandwidth_limit: user.config.bandwidth_limit,
        })
    }

    pub fn increment_connections(&self, username: &str) {
        if let Some(user) = self.users.get(username) {
            *user.active_connections.write() += 1;
        }
    }

    pub fn decrement_connections(&self, username: &str) {
        if let Some(user) = self.users.get(username) {
            let mut count = user.active_connections.write();
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    pub fn check_connection_limit(&self, username: &str) -> bool {
        if let Some(user) = self.users.get(username) {
            *user.active_connections.read() < self.config.max_connections_per_user
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserStats {
    pub username: String,
    pub active_connections: usize,
    pub total_bytes: u64,
    pub current_bandwidth: u64,
    pub bandwidth_limit: Option<u64>,
}
