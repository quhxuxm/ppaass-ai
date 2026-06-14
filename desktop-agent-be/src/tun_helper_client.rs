#[cfg(target_os = "macos")]
mod unix {
    use crate::config::TunConfig;
    use crate::error::{AgentError, Result};
    use common::BindInterface;
    use common::tun_control::{
        TUN_HELPER_DNS_STATE_FILE_NAME, TUN_HELPER_ROUTE_STATE_FILE_NAME, TunHelperRequest,
        TunHelperResponse, TunStartRequest, TunStartedResponse,
    };
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::io::{IoSliceMut, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use tun_rs::AsyncDevice;

    pub(crate) struct HelperTunDevice {
        pub(crate) device: AsyncDevice,
        pub(crate) name: String,
        pub(crate) if_index: u32,
        pub(crate) lease: HelperTunLease,
    }

    pub(crate) struct HelperTunLease {
        socket_path: String,
        lease_id: String,
    }

    impl Drop for HelperTunLease {
        fn drop(&mut self) {
            if let Err(err) = stop_tun(&self.socket_path, &self.lease_id) {
                tracing::warn!("通知 TUN helper 清理 lease={} 失败：{}", self.lease_id, err);
            }
        }
    }

    pub(crate) fn start_tun(
        config: &TunConfig,
        proxy_addrs: &[String],
        proxy_bind_interface: Option<&BindInterface>,
    ) -> Result<HelperTunDevice> {
        let request = TunHelperRequest::StartTun(TunStartRequest {
            name: config.name.clone(),
            ipv4: config.ipv4.clone(),
            ipv6: config.ipv6.clone(),
            mtu: config.mtu,
            proxy_addrs: proxy_addrs.to_vec(),
            proxy_dns: config.proxy_dns,
            proxy_bind_interface: proxy_bind_interface.cloned(),
            route_state_file: Some(resolve_state_file(
                config.route_state_file.as_deref(),
                TUN_HELPER_ROUTE_STATE_FILE_NAME,
            )?),
            dns_state_file: Some(resolve_state_file(
                config.dns_state_file.as_deref(),
                TUN_HELPER_DNS_STATE_FILE_NAME,
            )?),
        });

        let mut stream = UnixStream::connect(&config.macos_helper_socket).map_err(|e| {
            AgentError::Connection(format!(
                "连接 TUN helper 失败：socket={} error={e}",
                config.macos_helper_socket
            ))
        })?;
        write_frame(&mut stream, &request)?;
        let fd = recv_fd_marker(&stream)?;
        let response: TunHelperResponse = read_frame(&mut stream)?;

        match response {
            TunHelperResponse::TunStarted(TunStartedResponse {
                lease_id,
                name,
                if_index,
            }) => {
                let fd = fd.ok_or_else(|| {
                    AgentError::Connection("TUN helper 未返回 TUN 设备 fd".to_string())
                })?;
                let device = unsafe { AsyncDevice::from_fd(fd) }
                    .map_err(|e| AgentError::Connection(format!("接管 helper TUN fd 失败：{e}")))?;
                Ok(HelperTunDevice {
                    device,
                    name,
                    if_index,
                    lease: HelperTunLease {
                        socket_path: config.macos_helper_socket.clone(),
                        lease_id,
                    },
                })
            }
            TunHelperResponse::Error { message } => Err(AgentError::Connection(format!(
                "TUN helper 创建设备失败：{message}"
            ))),
            other => Err(AgentError::Connection(format!(
                "TUN helper 返回了意外响应：{other:?}"
            ))),
        }
    }

    pub(crate) fn refresh_macos_scoped_default_bypass(socket_path: &str) -> Result<()> {
        let mut stream = UnixStream::connect(socket_path).map_err(|e| {
            AgentError::Connection(format!(
                "连接 TUN helper 刷新 macOS scoped default 失败：{e}"
            ))
        })?;
        write_frame(
            &mut stream,
            &TunHelperRequest::RefreshMacosScopedDefaultBypass,
        )?;
        let _ = recv_fd_marker(&stream)?;
        let response: TunHelperResponse = read_frame(&mut stream)?;
        match response {
            TunHelperResponse::Ok => Ok(()),
            TunHelperResponse::Error { message } => Err(AgentError::Connection(message)),
            other => Err(AgentError::Connection(format!(
                "TUN helper 刷新 macOS scoped default 返回了意外响应：{other:?}"
            ))),
        }
    }

    fn stop_tun(socket_path: &str, lease_id: &str) -> Result<()> {
        let mut stream = UnixStream::connect(socket_path)
            .map_err(|e| AgentError::Connection(format!("连接 TUN helper 清理 lease 失败：{e}")))?;
        write_frame(
            &mut stream,
            &TunHelperRequest::StopTun {
                lease_id: lease_id.to_string(),
            },
        )?;
        let _ = recv_fd_marker(&stream)?;
        let response: TunHelperResponse = read_frame(&mut stream)?;
        match response {
            TunHelperResponse::Ok => Ok(()),
            TunHelperResponse::Error { message } => Err(AgentError::Connection(message)),
            other => Err(AgentError::Connection(format!(
                "TUN helper 清理 lease 返回了意外响应：{other:?}"
            ))),
        }
    }

    fn resolve_state_file(configured: Option<&str>, default_name: &str) -> Result<String> {
        let path = configured
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default_name));
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .map_err(|e| AgentError::Connection(format!("读取当前目录失败：{e}")))?
                .join(path)
        };
        Ok(path.to_string_lossy().into_owned())
    }

    fn write_frame(stream: &mut UnixStream, request: &TunHelperRequest) -> Result<()> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| AgentError::Connection(format!("序列化 TUN helper 请求失败：{e}")))?;
        write_raw_frame(stream, &payload)
    }

    fn write_raw_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
        let len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| AgentError::Connection("TUN helper 请求过大".to_string()))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(payload)?;
        Ok(())
    }

    fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            return Err(AgentError::Connection(format!(
                "TUN helper 响应过大：{len} bytes"
            )));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        serde_json::from_slice(&payload)
            .map_err(|e| AgentError::Connection(format!("解析 TUN helper 响应失败：{e}")))
    }

    fn recv_fd_marker(stream: &UnixStream) -> Result<Option<RawFd>> {
        let mut marker = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut marker)];
        let mut cmsgspace = nix::cmsg_space!([RawFd; 1]);
        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsgspace),
            MsgFlags::empty(),
        )
        .map_err(|e| AgentError::Connection(format!("接收 TUN helper fd 失败：{e}")))?;
        if msg.bytes == 0 {
            return Err(AgentError::Connection(
                "TUN helper 在发送 fd 前关闭连接".to_string(),
            ));
        }

        let mut received_fd = None;
        for cmsg in msg
            .cmsgs()
            .map_err(|e| AgentError::Connection(format!("解析 TUN helper fd 失败：{e}")))?
        {
            if let ControlMessageOwned::ScmRights(fds) = cmsg
                && let Some(fd) = fds.first()
            {
                received_fd = Some(*fd);
            }
        }

        Ok(received_fd)
    }
}

#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub(crate) use unix::{
    HelperTunDevice, HelperTunLease, refresh_macos_scoped_default_bypass, start_tun,
};
