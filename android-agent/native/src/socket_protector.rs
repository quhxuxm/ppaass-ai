use std::io;
use std::sync::Mutex;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::jint;
use jni::{JNIEnv, JavaVM};

struct SocketProtector {
    vm: JavaVM,
    service: GlobalRef,
}

static SOCKET_PROTECTOR: Mutex<Option<SocketProtector>> = Mutex::new(None);

pub fn install(env: &mut JNIEnv<'_>, service: JObject<'_>) -> jni::errors::Result<()> {
    let protector = SocketProtector {
        vm: env.get_java_vm()?,
        service: env.new_global_ref(service)?,
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
    let protector = SOCKET_PROTECTOR
        .lock()
        .map_err(|_| io::Error::other("Android socket protector mutex was poisoned"))?;
    let Some(protector) = protector.as_ref() else {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Android socket protector is not installed",
        ));
    };

    let mut env = protector
        .vm
        .attach_current_thread()
        .map_err(|err| io::Error::other(err.to_string()))?;
    let protected = env
        .call_method(
            protector.service.as_obj(),
            "protectSocket",
            "(I)Z",
            &[JValue::Int(fd as jint)],
        )
        .and_then(|value| value.z())
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

#[cfg(not(unix))]
pub fn protect_fd(_fd: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Android socket protection is only supported on Unix-like targets",
    ))
}
