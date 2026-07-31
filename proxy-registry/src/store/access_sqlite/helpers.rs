use super::*;

pub(super) fn normalize_access_target_host(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ACCESS_TARGET_HOST_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "target_host 必须为 1..={MAX_ACCESS_TARGET_HOST_BYTES} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidAccountField(
            "target_host 不能包含控制字符".to_string(),
        )
        .into());
    }
    Ok(value.to_ascii_lowercase())
}

pub(super) fn validate_retention_days(retention_days: u16) -> Result<()> {
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(ValidationError::InvalidAccountField(format!(
            "访问记录保留天数必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..=\
             {MAX_ACCESS_LOG_RETENTION_DAYS} 范围内"
        ))
        .into());
    }
    Ok(())
}

pub(super) fn parse_retention_days(value: &str) -> Result<u16> {
    let retention_days = value.parse::<u16>().map_err(|_| {
        UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 不是有效整数：{value}"
        ))
    })?;
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..=\
             {MAX_ACCESS_LOG_RETENTION_DAYS} 范围内，实际为 {retention_days}"
        )));
    }
    Ok(retention_days)
}

pub(super) fn row_to_access_record(row: SqliteRow) -> Result<AccessRecord> {
    let record_id: i64 = row.try_get("record_id")?;
    let protocol_encoded: String = row.try_get("protocol")?;
    let protocol = AccessProtocol::parse(&protocol_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "访问记录 {record_id} 的 protocol 值无效：{protocol_encoded}"
        ))
    })?;
    let target_port: i64 = row.try_get("target_port")?;
    let target_port = u16::try_from(target_port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!(
                "访问记录 {record_id} 的 target_port 值无效：{target_port}"
            ))
        })?;
    Ok(AccessRecord {
        record_id,
        username: row.try_get("username")?,
        protocol,
        target_host: row.try_get("target_host")?,
        target_port,
        access_count: u64::try_from(row.try_get::<i64, _>("access_count")?)
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "访问记录 {record_id} 的 access_count 无效"
                ))
            })?,
        accessed_at: row.try_get("accessed_at")?,
    })
}

pub(super) fn validate_checkpoint(
    (busy, log_frames, checkpointed_frames): (i64, i64, i64),
    database: &str,
) -> Result<()> {
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "{database} WAL checkpoint 未完成：busy={busy}, log={log_frames}, \
             checkpointed={checkpointed_frames}"
        )));
    }
    Ok(())
}

pub(super) fn same_database_path(left: &Path, right: &Path) -> Result<bool> {
    if left.try_exists()? && right.try_exists()? {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let left_metadata = fs::metadata(left)?;
            let right_metadata = fs::metadata(right)?;
            if left_metadata.dev() == right_metadata.dev()
                && left_metadata.ino() == right_metadata.ino()
            {
                return Ok(true);
            }
        }
        return Ok(fs::canonicalize(left)? == fs::canonicalize(right)?);
    }
    Ok(absolute_lexical_path(left)? == absolute_lexical_path(right)?)
}

pub(super) fn absolute_lexical_path(path: &Path) -> Result<PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

#[cfg(unix)]
pub(super) fn prepare_database_files(
    database_path: &Path,
    file_permissions: SqliteFilePermissions,
) -> Result<()> {
    let mode = file_permissions.unix_mode();
    secure_open_and_set_mode(database_path, mode, true)?;
    for path in database_sidecar_files(database_path) {
        secure_open_and_set_mode(&path, mode, false)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn prepare_database_files(
    _database_path: &Path,
    _file_permissions: SqliteFilePermissions,
) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn secure_open_and_set_mode(path: &Path, mode: u32, create: bool) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = OpenOptions::new();
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
        file.set_permissions(fs::Permissions::from_mode(mode))?;
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
