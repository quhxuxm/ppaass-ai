use std::sync::Mutex;

#[cfg(unix)]
use std::io;

use jni::JNIEnv;
#[cfg(unix)]
use jni::JavaVM;
use jni::objects::JObject;
#[cfg(unix)]
use jni::objects::{GlobalRef, JValue};
#[cfg(unix)]
use jni::sys::jint;

#[cfg(unix)]
struct SocketProtector {
    vm: JavaVM,
    service: GlobalRef,
}

#[cfg(not(unix))]
struct SocketProtector;

static SOCKET_PROTECTOR: Mutex<Option<SocketProtector>> = Mutex::new(None);

pub fn install(env: &mut JNIEnv<'_>, service: JObject<'_>) -> jni::errors::Result<()> {
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
