use std::sync::Mutex;

#[cfg(unix)]
use std::io;

use jni::Env;
#[cfg(unix)]
use jni::JavaVM;
use jni::objects::JObject;
#[cfg(unix)]
use jni::objects::{Global, JValue};
#[cfg(unix)]
use jni::sys::jint;

#[cfg(unix)]
struct SocketProtector {
    vm: JavaVM,
    service: Global<JObject<'static>>,
}

#[cfg(not(unix))]
struct SocketProtector;

static SOCKET_PROTECTOR: Mutex<Option<SocketProtector>> = Mutex::new(None);

pub fn install(env: &mut Env<'_>, service: JObject<'_>) -> jni::errors::Result<()> {
    #[cfg(unix)]
    let protector = SocketProtector {
        vm: env.get_java_vm()?,
        service: env.new_global_ref(service)?,
    };

    #[cfg(not(unix))]
    let protector = {
        let _ = env;
        let _ = service;
        SocketProtector
    };

    *SOCKET_PROTECTOR
        .lock()
        .expect("socket protector mutex poisoned") = Some(protector);
    Ok(())
}

pub fn clear() {
    *SOCKET_PROTECTOR
        .lock()
        .expect("socket protector mutex poisoned") = None;
}

#[cfg(unix)]
pub fn protect_fd(fd: std::os::fd::RawFd) -> io::Result<()> {
    protect_fd_impl(fd, false)
}

/// Native UDP transport is only created by the VPN netstack. It must never
/// continue without VpnService.protect(), otherwise its own encrypted packets
/// are captured by the TUN again and form a routing loop.
#[cfg(unix)]
pub fn protect_fd_required(fd: std::os::fd::RawFd) -> io::Result<()> {
    protect_fd_impl(fd, true)
}

#[cfg(unix)]
fn protect_fd_impl(fd: std::os::fd::RawFd, required: bool) -> io::Result<()> {
    let protector = SOCKET_PROTECTOR
        .lock()
        .map_err(|_| io::Error::other("Android socket protector mutex was poisoned"))?;
    let Some(protector) = protector.as_ref() else {
        // HTTP proxy mode can run without VpnService; in that case there is no socket to exclude.
        return if required {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService socket protector is not installed",
            ))
        } else {
            Ok(())
        };
    };

    let protected = protector
        .vm
        .attach_current_thread(|env| -> jni::errors::Result<bool> {
            let value = env.call_method(
                protector.service.as_obj(),
                jni::jni_str!("protectSocket"),
                jni::jni_sig!("(I)Z"),
                &[JValue::Int(fd as jint)],
            )?;
            value.z()
        })
        .map_err(|err| io::Error::other(err.to_string()))?;
    if protected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VpnService.protect returned false",
        ))
    }
}
