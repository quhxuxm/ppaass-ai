use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub username: String,
    pub public_key_pem: String,

    #[serde(default)]
    pub bandwidth_limit_mbps: Option<u64>, // Megabits per second
}
