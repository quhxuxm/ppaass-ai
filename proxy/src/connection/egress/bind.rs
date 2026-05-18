use socket2::Socket;
use std::io;
use std::net::SocketAddr;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::num::NonZeroU32;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(super) fn bind_socket_to_interface(
    socket: &Socket,
    interface: &str,
    _interface_index: Option<u32>,
    _dst: SocketAddr,
) -> io::Result<()> {
    // Linux/Android 通过 SO_BINDTODEVICE 将 socket 直接绑到设备名。
    if interface.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
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
pub(super) fn bind_socket_to_interface(
    socket: &Socket,
    interface: &str,
    interface_index: Option<u32>,
    dst: SocketAddr,
) -> io::Result<()> {
    // Apple 系统按 IPv4/IPv6 分别使用 if_index 绑定设备。
    let index = interface_index
        .and_then(NonZeroU32::new)
        .ok_or_else(|| io::Error::other(format!("网络设备 {interface} 没有有效 if_index")))?;

    if dst.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
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
)))]
pub(super) fn bind_socket_to_interface(
    _socket: &Socket,
    _interface: &str,
    _interface_index: Option<u32>,
    _dst: SocketAddr,
) -> io::Result<()> {
    // 其他平台没有统一的 socket 级设备绑定能力，只保留源地址绑定。
    Ok(())
}
