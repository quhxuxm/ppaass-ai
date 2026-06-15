use super::config::BindInterface;
use socket2::Socket;
use std::net::SocketAddr;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::num::NonZeroU32;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
#[cfg(windows)]
use tracing::debug;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR, setsockopt,
};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_interface_name(bind_interface: Option<&BindInterface>) -> Option<&str> {
    bind_interface?.name.as_deref()
}

#[cfg(any(
    windows,
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn bind_interface_index(bind_interface: Option<&BindInterface>) -> Option<u32> {
    bind_interface?.index
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub fn bind_socket_to_interface(
    socket: &Socket,
    bind_interface: Option<&BindInterface>,
    _dst: SocketAddr,
) -> std::io::Result<()> {
    let Some(interface) = bind_interface_name(bind_interface) else {
        return Ok(());
    };
    if interface.as_bytes().contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "网络设备名不能包含 NUL 字节",
        ));
    }
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
pub fn bind_socket_to_interface(
    socket: &Socket,
    bind_interface: Option<&BindInterface>,
    dst: SocketAddr,
) -> std::io::Result<()> {
    let Some(index) = bind_interface_index(bind_interface) else {
        return Ok(());
    };
    let Some(index) = NonZeroU32::new(index) else {
        return Ok(());
    };

    if dst.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(windows)]
pub fn bind_socket_to_interface(
    socket: &Socket,
    bind_interface: Option<&BindInterface>,
    dst: SocketAddr,
) -> std::io::Result<()> {
    let Some(index) = bind_interface_index(bind_interface) else {
        return Ok(());
    };
    if index == 0 {
        return Ok(());
    }

    let (level, option, value) = if dst.is_ipv4() {
        // Windows expects IP_UNICAST_IF as a DWORD in network byte order.
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    } else {
        // IPV6_UNICAST_IF uses the interface index in host byte order.
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    };

    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            option,
            (&value as *const u32).cast(),
            std::mem::size_of_val(&value) as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }

    debug!("已将 socket 绑定到 Windows if_index={index} (dst={dst})");
    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    windows,
)))]
pub fn bind_socket_to_interface(
    _socket: &Socket,
    _bind_interface: Option<&BindInterface>,
    _dst: SocketAddr,
) -> std::io::Result<()> {
    Ok(())
}
