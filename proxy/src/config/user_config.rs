use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// 认证用户名，必须与 users.toml 中的表键一致。
    pub username: String,

    /// proxy 用该公钥解开 agent 发来的会话密钥。
    pub public_key_pem: String,

    /// 为空表示不限速；有值时按 Mbps 做粗粒度秒级限制。
    #[serde(default)]
    pub bandwidth_limit_mbps: Option<u64>,
}
