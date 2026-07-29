use super::*;

pub(super) fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        match fs::symlink_metadata(parent) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    anyhow::bail!(
                        "TUN helper socket 目录必须是实际目录，拒绝符号链接或非目录：{}",
                        parent.display()
                    );
                }
                if effective_uid() == 0 && metadata.uid() != 0 {
                    anyhow::bail!(
                        "TUN helper socket 目录不是 root 所有，拒绝在不受信任目录运行：{} uid={}",
                        parent.display(),
                        metadata.uid()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(parent).with_context(|| {
                    format!("创建 helper socket 目录失败：{}", parent.display())
                })?;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("检查 helper socket 目录失败：{}", parent.display()));
            }
        }
        let metadata = fs::metadata(parent)
            .with_context(|| format!("读取 helper socket 目录失败：{}", parent.display()))?;
        if effective_uid() == 0 && metadata.uid() != 0 {
            anyhow::bail!(
                "TUN helper socket 目录不是 root 所有，拒绝在不受信任目录运行：{} uid={}",
                parent.display(),
                metadata.uid()
            );
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("设置 helper socket 目录权限失败：{}", parent.display()))?;
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("删除旧 helper socket 失败：{}", path.display()));
        }
    }
    Ok(())
}

pub(super) fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("helper 请求过大：{len} bytes");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

pub(super) fn send_response(
    stream: &UnixStream,
    response: &TunHelperResponse,
    fd: Option<RawFd>,
) -> Result<()> {
    send_fd_marker(stream, fd)?;

    let payload = serde_json::to_vec(response)?;
    let len: u32 = payload.len().try_into().context("helper 响应过大")?;
    let mut stream = stream;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

pub(super) fn send_fd_marker(stream: &UnixStream, fd: Option<RawFd>) -> Result<()> {
    let marker = [1u8];
    let iov = [IoSlice::new(&marker)];
    if let Some(fd) = fd {
        let fds = [fd];
        sendmsg::<()>(
            stream.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )?;
    } else {
        sendmsg::<()>(stream.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)?;
    }
    Ok(())
}

pub(super) fn authorize_peer(stream: &UnixStream, allowed_uid: Option<u32>) -> Result<()> {
    let Some(allowed_uid) = allowed_uid else {
        return Ok(());
    };
    let uid = peer_uid(stream)?;
    if uid == 0 || uid == allowed_uid {
        return Ok(());
    }
    anyhow::bail!("uid={uid} 无权使用 helper，允许 uid={allowed_uid}");
}

#[cfg(target_os = "linux")]
pub(super) fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    Ok(getsockopt(stream, PeerCredentials)?.uid())
}

#[cfg(target_os = "macos")]
pub(super) fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    Ok(getsockopt(stream, LocalPeerCred)?.uid())
}

#[cfg(target_os = "macos")]
pub(super) fn peer_pid(stream: &UnixStream) -> Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};
    let pid = getsockopt(stream, LocalPeerPid)?;
    u32::try_from(pid).context("helper 客户端 PID 无效")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn peer_uid(_stream: &UnixStream) -> Result<u32> {
    anyhow::bail!("当前 Unix 平台暂未实现 helper peer credential 校验")
}

pub(super) fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub(super) fn init_tracing(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::new(log_level);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
