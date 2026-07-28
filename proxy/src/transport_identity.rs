use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use protocol::RsaKeyPair;

use crate::error::{ProxyError, Result};

const MAX_TRANSPORT_IDENTITY_PEM_SIZE: u64 = 64 * 1024;

/// Load the Proxy signing identity without following a final-component
/// symlink. Error messages deliberately omit parser details and PEM contents.
pub(crate) fn load_transport_identity_private_key(path: &Path) -> Result<RsaKeyPair> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|_| {
        ProxyError::Configuration(format!(
            "无法安全读取 Proxy 传输身份私钥文件 {}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|_| {
        ProxyError::Configuration(format!(
            "无法检查 Proxy 传输身份私钥文件 {}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TRANSPORT_IDENTITY_PEM_SIZE {
        return Err(ProxyError::Configuration(format!(
            "Proxy 传输身份私钥必须是受限大小的普通文件：{}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProxyError::Configuration(format!(
                "Proxy 传输身份私钥不能授予 group/world 任何权限：{}",
                path.display()
            )));
        }
        // SAFETY: geteuid has no preconditions and only reads process state.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(ProxyError::Configuration(format!(
                "Proxy 传输身份私钥必须属于当前服务用户：{}",
                path.display()
            )));
        }
    }

    let mut pem = String::new();
    file.take(MAX_TRANSPORT_IDENTITY_PEM_SIZE + 1)
        .read_to_string(&mut pem)
        .map_err(|_| {
            ProxyError::Configuration(format!(
                "Proxy 传输身份私钥文件不是有效 UTF-8：{}",
                path.display()
            ))
        })?;
    if pem.len() as u64 > MAX_TRANSPORT_IDENTITY_PEM_SIZE {
        return Err(ProxyError::Configuration(format!(
            "Proxy 传输身份私钥文件过大：{}",
            path.display()
        )));
    }
    let identity = RsaKeyPair::from_private_key_pem(&pem).map_err(|_| {
        ProxyError::Configuration(format!(
            "Proxy 传输身份私钥不是有效 PKCS#8 PEM：{}",
            path.display()
        ))
    })?;
    if !(256..=1_024).contains(&identity.modulus_size()) {
        return Err(ProxyError::Configuration(
            "Proxy 传输身份 RSA 密钥必须为 2048 到 8192 位".to_string(),
        ));
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn loads_a_restricted_pkcs8_identity() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("transport-identity.pem");
        let key = RsaKeyPair::generate(2048).unwrap();
        fs::write(&path, key.private_key_to_pem().unwrap()).unwrap();
        #[cfg(unix)]
        set_mode(&path, 0o600);

        assert!(load_transport_identity_private_key(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_world_permissions_and_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("transport-identity.pem");
        let link = directory.path().join("identity-link.pem");
        let key = RsaKeyPair::generate(2048).unwrap();
        fs::write(&path, key.private_key_to_pem().unwrap()).unwrap();
        set_mode(&path, 0o644);
        assert!(load_transport_identity_private_key(&path).is_err());

        set_mode(&path, 0o600);
        symlink(&path, &link).unwrap();
        assert!(load_transport_identity_private_key(&link).is_err());
    }
}
