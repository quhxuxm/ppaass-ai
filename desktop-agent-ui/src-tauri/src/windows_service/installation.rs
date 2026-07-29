use super::*;

pub(crate) fn launch_elevated_service_installer(config_root: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let cwd = std::env::current_dir().map_err(|err| format!("定位工作目录失败：{err}"))?;
    let args = format!(
        "{INSTALL_SERVICE_ARG} {SERVICE_CONFIG_ROOT_ARG} \"{}\"",
        config_root.display()
    );

    let operation = wide_null("runas");
    let exe = wide_null(exe.as_os_str());
    let args = wide_null(args);
    let cwd = wide_null(cwd.as_os_str());

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            cwd.as_ptr(),
            0,
        )
    };

    if result as isize <= 32 {
        return Err(format!(
            "请求管理员权限启动服务失败：ShellExecuteW 返回 {result:?}"
        ));
    }
    Ok(())
}

pub(crate) fn windows_service_matches_installation(config_root: &Path) -> Result<bool, String> {
    if !windows_service_matches_current_exe()? {
        return Ok(false);
    }
    let output = run_sc_capture(["qc", SERVICE_NAME])?;
    let command_line = parse_sc_binary_path(&output)
        .ok_or_else(|| "无法读取 PPAASS Agent Windows Service 路径".to_string())?;
    let Some(service_config_root) =
        extract_command_argument_path(command_line, SERVICE_CONFIG_ROOT_ARG)
    else {
        return Ok(false);
    };
    Ok(normalized_path_for_compare(config_root)
        == normalized_path_for_compare(Path::new(&service_config_root))
        && sc_service_is_auto_start(&output))
}

pub(crate) fn sc_service_is_auto_start(output: &str) -> bool {
    output.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("START_TYPE")
                && (value.trim_start().starts_with('2')
                    || value.to_ascii_uppercase().contains("AUTO_START"))
        })
    })
}

pub(crate) fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn run_sc<const N: usize>(args: [&str; N]) -> Result<(), String> {
    run_sc_capture(args).map(|_| ())
}

pub(crate) fn run_sc_capture<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let output = Command::new("sc.exe")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| format!("执行 sc.exe 失败：{err}"))?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "sc.exe 失败：{}{}{}",
        output.status,
        if stdout.trim().is_empty() { "" } else { "\n" },
        if stdout.trim().is_empty() {
            stderr.trim()
        } else {
            stdout.trim()
        }
    ))
}

pub(crate) fn parse_sc_binary_path(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        if !line.contains("BINARY_PATH_NAME") {
            return None;
        }
        line.split_once(':').map(|(_, value)| value.trim())
    })
}

pub(crate) fn extract_service_exe_path(command_line: &str) -> Option<String> {
    let command_line = command_line.trim();
    if command_line.is_empty() {
        return None;
    }

    if let Some(rest) = command_line.strip_prefix('"') {
        let (path, _) = rest.split_once('"')?;
        return Some(path.to_string());
    }

    command_line
        .split_whitespace()
        .next()
        .map(|path| path.to_string())
}

pub(crate) fn extract_command_argument_path(command_line: &str, argument: &str) -> Option<String> {
    let (_, remaining) = command_line.split_once(argument)?;
    let remaining = remaining.trim_start();
    if let Some(quoted) = remaining.strip_prefix('"') {
        return quoted
            .split_once('"')
            .map(|(value, _)| value.to_string())
            .filter(|value| !value.is_empty());
    }
    remaining
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

pub(crate) fn normalized_path_for_compare(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

pub(crate) fn trusted_service_executable() -> Result<PathBuf, String> {
    let executable = fs::canonicalize(
        std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?,
    )
    .map_err(|err| format!("解析 UI 程序路径失败：{err}"))?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let trusted = program_files_roots()
        .iter()
        .any(|root| normalized_path_is_within(install_dir, root));
    if !trusted {
        return Err(
            "拒绝将用户可写目录中的程序注册为 SYSTEM 服务；请使用正式安装包安装到 Program Files"
                .to_string(),
        );
    }
    Ok(executable)
}

pub(crate) fn trusted_windows_wintun_path() -> Result<PathBuf, String> {
    let executable = trusted_service_executable()?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let wintun = fs::canonicalize(install_dir.join("wintun.dll"))
        .map_err(|err| format!("可信安装目录缺少 wintun.dll：{err}"))?;
    if wintun.parent() != Some(install_dir) || !wintun.is_file() {
        return Err("wintun.dll 必须是可信安装目录中的普通文件".to_string());
    }
    Ok(wintun)
}

pub(crate) fn program_files_roots() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter_map(|path| fs::canonicalize(path).ok())
        .fold(Vec::new(), |mut roots, path| {
            if !roots.iter().any(|existing| {
                normalized_path_for_compare(existing) == normalized_path_for_compare(&path)
            }) {
                roots.push(path);
            }
            roots
        })
}

pub(crate) fn verify_interactive_installation_is_protected() -> Result<(), String> {
    let executable = trusted_service_executable()?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let wintun = trusted_windows_wintun_path()?;
    if unsafe { IsUserAnAdmin() } != 0 {
        return Ok(());
    }

    match TempFileBuilder::new()
        .prefix(".ppaass-write-probe-")
        .tempfile_in(install_dir)
    {
        Ok(_) => return Err("Agent 安装目录可被当前普通用户写入，拒绝启动 SYSTEM 服务".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(format!("无法验证 Agent 安装目录写保护：{error}")),
    }

    match fs::OpenOptions::new().write(true).open(&wintun) {
        Ok(_) => Err("wintun.dll 可被当前普通用户替换，拒绝启动 SYSTEM 服务".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(format!("无法验证 wintun.dll 写保护：{error}")),
    }
}

pub(crate) fn stop_windows_service_if_running() -> Result<(), String> {
    match run_sc(["stop", SERVICE_NAME]) {
        Ok(()) => wait_windows_service_stopped(),
        Err(err) if err.contains("1062") || err.contains("has not been started") => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn wait_windows_service_stopped() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let query = run_sc_capture(["query", SERVICE_NAME])?;
        if query.contains("STOPPED") {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    Err("等待 PPAASS Agent Windows Service 停止超时".to_string())
}
