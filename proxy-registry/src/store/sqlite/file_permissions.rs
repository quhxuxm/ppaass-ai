#[cfg(unix)]
use super::*;

#[cfg(unix)]
pub(super) fn secure_open_and_set_mode(
    path: &Path,
    mode: u32,
    create: bool,
) -> std::io::Result<()> {
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create {
        options.create(true);
    }

    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "无法安全打开 SQLite 数据文件 {}（拒绝符号链接）：{error}",
                    path.display()
                ),
            ));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SQLite 数据路径不是普通文件：{}", path.display()),
        ));
    }
    let actual_mode = metadata.permissions().mode() & 0o7777;
    if actual_mode != mode {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "无法把 SQLite 数据文件 {} 的权限从 {actual_mode:04o} 调整为 \
                         {mode:04o}：{error}",
                        path.display()
                    ),
                )
            })?;
    }
    Ok(())
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

#[cfg(unix)]
pub(super) fn database_files(database_path: &Path) -> [PathBuf; 4] {
    let [wal, shm, journal] = database_sidecar_files(database_path);
    [database_path.to_path_buf(), wal, shm, journal]
}
