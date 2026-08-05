use super::*;

pub fn write_private_key_to_dir(
    credentials_dir: &Path,
    file_name: &str,
    private_key_pem: &str,
) -> Result<PathBuf, String> {
    fs::create_dir_all(credentials_dir).map_err(|error| format!("创建私钥目录失败：{error}"))?;
    #[cfg(unix)]
    fs::set_permissions(credentials_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置私钥目录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(credentials_dir, true)?;

    let destination = credentials_dir.join(file_name);
    let mut temporary = Builder::new()
        .prefix(".managed-private-key-")
        .tempfile_in(credentials_dir)
        .map_err(|error| format!("创建私钥临时文件失败：{error}"))?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置私钥临时文件权限失败：{error}"))?;
    temporary
        .write_all(private_key_pem.as_bytes())
        .map_err(|error| format!("写入私钥失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步私钥到磁盘失败：{error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("保存私钥失败：{}", error.error))?;
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置私钥权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(&destination, false)?;
    if let Ok(directory) = fs::File::open(credentials_dir) {
        let _ = directory.sync_all();
    }
    Ok(destination)
}

pub(crate) fn cleanup_old_managed_private_keys(current_private_key: &Path) {
    let Some(credentials_dir) = current_private_key.parent() else {
        return;
    };
    let Some(current_file_name) = current_private_key
        .file_name()
        .and_then(|value| value.to_str())
    else {
        return;
    };
    remove_other_managed_private_keys(credentials_dir, current_file_name);
}

pub fn remove_other_managed_private_keys(credentials_dir: &Path, current_file_name: &str) {
    let Ok(entries) = fs::read_dir(credentials_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.starts_with("managed-")
            && file_name.ends_with(".pem")
            && file_name != current_file_name
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(windows)]
pub(crate) fn set_windows_restricted_acl(path: &Path, directory: bool) -> Result<(), String> {
    let user_sid = windows_current_user_sid()?;
    let user_permission = if directory {
        format!("*{user_sid}:(OI)(CI)F")
    } else {
        format!("*{user_sid}:F")
    };
    let system_permission = if directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(user_permission)
        .arg(system_permission)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("设置 Windows 私钥 ACL 失败：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "设置 Windows 私钥 ACL 失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(windows)]
pub(crate) fn windows_current_user_sid() -> Result<String, String> {
    let output = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("读取当前 Windows 用户 SID 失败：{error}"))?;
    if !output.status.success() {
        return Err("读取当前 Windows 用户 SID 失败".to_string());
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let sid = line
        .trim()
        .rsplit(',')
        .next()
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| value.starts_with("S-1-"))
        .ok_or_else(|| "当前 Windows 用户 SID 格式无效".to_string())?;
    Ok(sid.to_string())
}

pub(crate) fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
