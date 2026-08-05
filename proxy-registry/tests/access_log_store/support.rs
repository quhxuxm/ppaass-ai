use protocol::RsaKeyPair;
use proxy_registry::{AccessProtocol, NewAccessRecord};
#[cfg(unix)]
use std::path::{Path, PathBuf};

pub(super) const LEGACY_USER_DATABASE_CHECKPOINT_KEY: &str = "access_log_split_checkpoint_v1";

pub(super) fn record(username: &str, host: &str, accessed_at: i64) -> NewAccessRecord {
    NewAccessRecord {
        username: username.to_string(),
        protocol: AccessProtocol::Tcp,
        target_host: host.to_string(),
        target_port: 443,
        accessed_at,
    }
}

pub(super) fn public_key() -> String {
    RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
}

#[cfg(unix)]
pub(super) fn database_sidecar_files(database_path: &Path) -> [PathBuf; 3] {
    let auxiliary_path = |suffix: &str| {
        let mut path = database_path.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    };
    [
        auxiliary_path("-wal"),
        auxiliary_path("-shm"),
        auxiliary_path("-journal"),
    ]
}
