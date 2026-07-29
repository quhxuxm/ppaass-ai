use super::*;

#[derive(Serialize)]
pub(crate) struct ServiceRequestEnvelopeRef<'a> {
    pub(crate) auth_token: &'a str,
    pub(crate) request: &'a ServiceRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceRequestEnvelope {
    pub(crate) auth_token: String,
    pub(crate) request: ServiceRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceSessionAuthorization {
    pub(crate) version: u8,
    pub(crate) token: String,
    #[serde(
        default,
        rename = "ui_process_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) _legacy_ui_process_id: Option<u32>,
    #[serde(
        default,
        rename = "ui_process_creation_time",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) _legacy_ui_process_creation_time: Option<u64>,
    #[serde(
        default,
        rename = "expires_at",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) _legacy_expires_at: Option<i64>,
}

impl Drop for ServiceSessionAuthorization {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceLoginBinding {
    pub(crate) username: String,
    pub(crate) key_version: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceDesiredState {
    pub(crate) version: u8,
    pub(crate) desired_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_version: Option<i64>,
}

define_windows_service!(ffi_service_main, windows_service_main);

pub(crate) fn windows_service_entrypoint() -> extern "system" fn(u32, *mut *mut u16) {
    ffi_service_main
}

pub(crate) fn activate_windows_service_session(app: &tauri::AppHandle) -> Result<(), String> {
    let mut random = [0_u8; SERVICE_SESSION_TOKEN_BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| format!("生成 Windows Service 会话令牌失败：{error}"))?;
    let token = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    random.zeroize();

    let path = ui_service_session_file_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Windows Service 会话文件缺少父目录".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建 Windows Service 会话目录失败：{error}"))?;
    set_windows_restricted_acl(parent, true)?;

    let authorization = ServiceSessionAuthorization {
        version: SERVICE_SESSION_FILE_VERSION,
        token: token.clone(),
        // Older files bound authorization to one UI PID. These fields are
        // decoded below only so an in-place upgrade can keep the already
        // authenticated Service running. The token now belongs to the durable
        // login and is revoked only by explicit logout.
        _legacy_ui_process_id: None,
        _legacy_ui_process_creation_time: None,
        // Kept for backwards-compatible decoding of existing files only.
        // Account/key expiry is decided by Proxy, never by the local clock.
        _legacy_expires_at: None,
    };
    let mut serialized = serde_json::to_vec(&authorization)
        .map_err(|error| format!("编码 Windows Service 会话失败：{error}"))?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".service-session-")
        .tempfile_in(parent)
        .map_err(|error| format!("创建 Windows Service 会话临时文件失败：{error}"))?;
    set_windows_restricted_acl(temporary.path(), false)?;
    temporary
        .write_all(&serialized)
        .map_err(|error| format!("写入 Windows Service 会话失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步 Windows Service 会话失败：{error}"))?;
    serialized.zeroize();

    if path.exists() {
        revoke_service_session_file(&path)?;
    }
    temporary
        .persist(&path)
        .map_err(|error| format!("保存 Windows Service 会话失败：{}", error.error))?;
    set_windows_restricted_acl(&path, false)?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }

    *UI_SERVICE_SESSION_TOKEN
        .lock()
        .map_err(|_| "Windows Service 会话令牌锁已损坏".to_string())? = Some(Zeroizing::new(token));
    Ok(())
}

pub(crate) fn invalidate_windows_service_session(app: &tauri::AppHandle) -> Result<(), String> {
    let desired_result = clear_ui_service_desired_running(app);
    let session_result =
        ui_service_session_file_path(app).and_then(|path| revoke_service_session_file(&path));
    if let Ok(mut token) = UI_SERVICE_SESSION_TOKEN.lock() {
        token.take();
    }
    match (desired_result, session_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(desired_error), Ok(())) => Err(desired_error),
        (Ok(()), Err(session_error)) => Err(session_error),
        (Err(desired_error), Err(session_error)) => Err(format!(
            "{desired_error}；同时吊销 Windows Service 会话失败：{session_error}"
        )),
    }
}

pub(crate) fn ui_service_session_file_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|path| path.join("credentials").join(SERVICE_SESSION_FILE_NAME))
        .map_err(|error| format!("定位 Windows Service 会话目录失败：{error}"))
}

pub(crate) fn clear_ui_service_desired_running(app: &tauri::AppHandle) -> Result<(), String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map(|path| {
            path.join("credentials")
                .join(SERVICE_DESIRED_STATE_FILE_NAME)
        })
        .map_err(|error| format!("定位 Windows Service 运行状态目录失败：{error}"))?;
    match fs::symlink_metadata(&path) {
        Ok(_) => persist_service_desired_state(&path, None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("读取 Windows Service 运行状态失败：{error}")),
    }
}

pub(crate) fn revoke_service_session_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(remove_error) => {
            let revoke_result = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .and_then(|mut file| {
                    file.write_all(b"{\"revoked\":true}")?;
                    file.sync_all()
                });
            match revoke_result {
                Ok(()) => Err(format!(
                    "删除 Windows Service 会话文件失败，已将其吊销：{remove_error}"
                )),
                Err(revoke_error) => Err(format!(
                    "无法吊销 Windows Service 会话：删除失败（{remove_error}），覆盖失败（{revoke_error}）"
                )),
            }
        }
    }
}
