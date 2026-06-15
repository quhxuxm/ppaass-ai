use crate::error::{AgentError, Result};
use tracing::info;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(unix)]
use std::process::Command;

pub fn ensure_tun_privileges_or_relaunch() -> Result<()> {
    if is_elevated() {
        return Ok(());
    }

    relaunch_elevated()?;
    std::process::exit(0);
}

#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(unix)]
fn is_elevated() -> bool {
    current_uid() == Some(0)
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    let output = Command::new("id").arg("-u").output().ok()?;
    let uid = String::from_utf8(output.stdout).ok()?;
    uid.trim().parse::<u32>().ok()
}

#[cfg(windows)]
fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| {
        AgentError::Connection(format!("请求管理员权限失败：无法定位当前程序：{e}"))
    })?;
    let cwd = std::env::current_dir().map_err(|e| {
        AgentError::Connection(format!("请求管理员权限失败：无法定位当前工作目录：{e}"))
    })?;
    let args = std::env::args_os()
        .skip(1)
        .map(quote_windows_arg)
        .collect::<Vec<_>>()
        .join(" ");

    let operation = wide_null("runas");
    let exe = wide_null(exe.as_os_str());
    let args = wide_null(args);
    let cwd = wide_null(cwd.as_os_str());

    info!("TUN 模式需要管理员权限，正在触发 UAC 提权并重启 agent");
    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            cwd.as_ptr(),
            1,
        )
    };

    if result as isize <= 32 {
        return Err(AgentError::Connection(format!(
            "请求管理员权限失败：ShellExecuteW 返回 {result:?}"
        )));
    }

    Ok(())
}

#[cfg(unix)]
fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| {
        AgentError::Connection(format!("请求 root 权限失败：无法定位当前程序：{e}"))
    })?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();

    info!("TUN 模式需要 root 权限，正在通过 sudo 重启 agent");
    let status = Command::new("sudo")
        .arg(exe)
        .args(args)
        .status()
        .map_err(|e| AgentError::Connection(format!("请求 root 权限失败：无法执行 sudo：{e}")))?;

    if !status.success() {
        return Err(AgentError::Connection(format!(
            "请求 root 权限失败：sudo 退出状态为 {status}"
        )));
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn is_elevated() -> bool {
    true
}

#[cfg(not(any(unix, windows)))]
fn relaunch_elevated() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn quote_windows_arg(arg: OsString) -> String {
    let raw = arg.to_string_lossy();
    if raw.is_empty() || raw.chars().any(|c| c.is_whitespace() || c == '"') {
        let mut quoted = String::from("\"");
        let mut backslashes = 0;
        for ch in raw.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                    quoted.push('"');
                    backslashes = 0;
                }
                _ => {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    quoted.push(ch);
                }
            }
        }
        quoted.push_str(&"\\".repeat(backslashes * 2));
        quoted.push('"');
        quoted
    } else {
        raw.into_owned()
    }
}
