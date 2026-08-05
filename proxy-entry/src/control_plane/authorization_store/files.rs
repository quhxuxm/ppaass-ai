use std::{fs::OpenOptions, path::Path, time::Duration};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use super::database_config_error;
use crate::error::{ProxyError, Result};

pub(super) async fn open_database(path: &Path) -> Result<(sqlx::SqlitePool, bool)> {
    if path.as_os_str().is_empty() {
        return Err(ProxyError::Configuration(
            "authorization_database_path 不能为空".to_string(),
        ));
    }
    create_parent_directory(path)?;
    let is_new = create_private_database_file(path)?;
    tighten_database_permissions(path)?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(4)
        .connect_with(options)
        .await
        .map_err(|error| database_config_error(path, "打开", error))?;
    Ok((pool, is_new))
}

fn create_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            ProxyError::Configuration(format!(
                "创建 Entry 授权数据库目录 {} 失败：{error}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

fn create_private_database_file(path: &Path) -> Result<bool> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).map_err(|metadata_error| {
                ProxyError::Configuration(format!(
                    "读取 Entry 授权数据库 {} 失败：{metadata_error}",
                    path.display()
                ))
            })?;
            if !metadata.file_type().is_file() {
                return Err(ProxyError::Configuration(format!(
                    "Entry 授权数据库路径不是普通文件：{}",
                    path.display()
                )));
            }
            Ok(metadata.len() == 0)
        }
        Err(error) => Err(ProxyError::Configuration(format!(
            "创建 Entry 授权数据库 {} 失败：{error}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
pub(super) fn tighten_database_permissions(path: &Path) -> Result<()> {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_file() => {
                std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
                    .map_err(|error| {
                        ProxyError::Configuration(format!(
                            "收紧 Entry 授权数据库权限 {} 失败：{error}",
                            candidate.display()
                        ))
                    })?;
            }
            Ok(_) => {
                return Err(ProxyError::Configuration(format!(
                    "Entry 授权数据库或 sidecar 路径不是普通文件：{}",
                    candidate.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ProxyError::Configuration(format!(
                    "读取 Entry 授权数据库权限 {} 失败：{error}",
                    candidate.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn tighten_database_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
