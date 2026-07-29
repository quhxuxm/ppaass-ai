use jni::objects::{JClass, JObject, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{Env, EnvUnowned};
use protocol::RsaKeyPair;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::authentication::{
    VerifiedAuthenticationState, monitor_verified_authentication_statuses,
};
use crate::config::AndroidAgentConfig;
use crate::fd_device::RawFd;
use crate::http_proxy::run_android_http_proxy;
use crate::http_proxy_clients::{
    block_http_proxy_client, http_proxy_clients_json, unblock_http_proxy_client,
};
use crate::netstack::run_android_agent;
use crate::packet_capture;
use crate::socket_protector;
use crate::traffic_stats;

struct AgentHandle {
    shutdown: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
    clear_socket_protector_on_stop: bool,
    authentication_state: Arc<VerifiedAuthenticationState>,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_validateKeyPair<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    private_key_pem: JString<'local>,
    public_key_pem: JString<'local>,
) -> jboolean {
    crate::android_log::install_tracing();
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        let private_key_pem = private_key_pem.try_to_string(env)?;
        let public_key_pem = public_key_pem.try_to_string(env)?;
        Ok(validate_key_pair(&private_key_pem, &public_key_pem))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn validate_key_pair(private_key_pem: &str, public_key_pem: &str) -> bool {
    let Ok(private_key) = RsaKeyPair::from_private_key_pem(private_key_pem) else {
        return false;
    };
    if RsaKeyPair::from_public_key_pem(public_key_pem).is_err() {
        return false;
    }
    let Ok(derived_public_key) = private_key.public_key_to_pem() else {
        return false;
    };
    normalize_pem(&derived_public_key) == normalize_pem(public_key_pem)
}

fn normalize_pem(value: &str) -> String {
    value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_start<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    vpn_service: JObject<'local>,
) -> jlong {
    crate::android_log::install_tracing();
    env.with_env(|env| -> jni::errors::Result<jlong> {
        Ok(start_agent(env, tun_fd, config_json, vpn_service))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn start_agent<'local>(
    env: &mut Env<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    vpn_service: JObject<'local>,
) -> jlong {
    let json: String = match config_json.try_to_string(env) {
        Ok(value) => value,
        Err(err) => {
            throw(env, format!("failed to read config JSON: {err}"));
            return 0;
        }
    };

    let config: AndroidAgentConfig = match serde_json::from_str(&json) {
        Ok(config) => config,
        Err(err) => {
            throw(env, format!("invalid config JSON: {err}"));
            return 0;
        }
    };

    if let Err(err) = socket_protector::install(env, vpn_service) {
        throw(
            env,
            format!("failed to install Android socket protector: {err}"),
        );
        return 0;
    }

    let async_runtime_stack_size = config.async_runtime_stack_size_mb.max(1) * 1024 * 1024;
    let runtime_threads = config.runtime_threads.max(1);
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let authentication_state = Arc::new(VerifiedAuthenticationState::default());
    let task_authentication_state = authentication_state.clone();
    let authentication_username = config.username.clone();
    let raw_fd = tun_fd as RawFd;
    let thread = match std::thread::Builder::new()
        .name("ppaass-android-agent".to_string())
        .stack_size(async_runtime_stack_size)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ppaass-android-agent-worker")
                .thread_stack_size(async_runtime_stack_size)
                .worker_threads(runtime_threads)
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!(error = %err, "failed to create Android Agent Tokio runtime");
                    return;
                }
            };

            let monitor_shutdown = task_shutdown.clone();
            let authentication_statuses = common::subscribe_verified_proxy_auth_statuses();
            let result = runtime.block_on(async move {
                let authentication_monitor =
                    tokio::spawn(monitor_verified_authentication_statuses(
                        task_authentication_state,
                        authentication_username,
                        authentication_statuses,
                        monitor_shutdown,
                    ));
                let result = run_android_agent(raw_fd, config, task_shutdown.clone()).await;
                task_shutdown.cancel();
                let _ = authentication_monitor.await;
                result
            });
            if let Err(err) = result {
                tracing::error!(error = %err, "Android Agent stopped");
            }
        }) {
        Ok(thread) => thread,
        Err(err) => {
            socket_protector::clear();
            throw(env, format!("failed to spawn native agent thread: {err}"));
            return 0;
        }
    };

    Box::into_raw(Box::new(AgentHandle {
        shutdown,
        thread: Some(thread),
        clear_socket_protector_on_stop: true,
        authentication_state,
    })) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_startHttpProxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    listen_port: jint,
) -> jlong {
    crate::android_log::install_tracing();
    env.with_env(|env| -> jni::errors::Result<jlong> {
        Ok(start_http_proxy(env, config_json, listen_port))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn start_http_proxy<'local>(
    env: &mut Env<'local>,
    config_json: JString<'local>,
    listen_port: jint,
) -> jlong {
    if listen_port <= 0 || listen_port > u16::MAX as jint {
        throw(
            env,
            format!("invalid HTTP proxy listen port: {listen_port}"),
        );
        return 0;
    }

    let json: String = match config_json.try_to_string(env) {
        Ok(value) => value,
        Err(err) => {
            throw(env, format!("failed to read HTTP proxy config JSON: {err}"));
            return 0;
        }
    };

    let config: AndroidAgentConfig = match serde_json::from_str(&json) {
        Ok(config) => config,
        Err(err) => {
            throw(env, format!("invalid HTTP proxy config JSON: {err}"));
            return 0;
        }
    };

    let async_runtime_stack_size = config.async_runtime_stack_size_mb.max(1) * 1024 * 1024;
    let runtime_threads = config.runtime_threads.max(1);
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let authentication_state = Arc::new(VerifiedAuthenticationState::default());
    let task_authentication_state = authentication_state.clone();
    let authentication_username = config.username.clone();
    let port = listen_port as u16;
    let thread = match std::thread::Builder::new()
        .name("ppaass-android-http-proxy".to_string())
        .stack_size(async_runtime_stack_size)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ppaass-android-http-proxy-worker")
                .thread_stack_size(async_runtime_stack_size)
                .worker_threads(runtime_threads)
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "failed to create Android HTTP proxy Tokio runtime"
                    );
                    return;
                }
            };

            let monitor_shutdown = task_shutdown.clone();
            let authentication_statuses = common::subscribe_verified_proxy_auth_statuses();
            let result = runtime.block_on(async move {
                let authentication_monitor =
                    tokio::spawn(monitor_verified_authentication_statuses(
                        task_authentication_state,
                        authentication_username,
                        authentication_statuses,
                        monitor_shutdown,
                    ));
                let result = run_android_http_proxy(config, port, task_shutdown.clone()).await;
                task_shutdown.cancel();
                let _ = authentication_monitor.await;
                result
            });
            if let Err(err) = result {
                tracing::error!(error = %err, "Android HTTP proxy stopped");
            }
        }) {
        Ok(thread) => thread,
        Err(err) => {
            throw(
                env,
                format!("failed to spawn native HTTP proxy thread: {err}"),
            );
            return 0;
        }
    };

    Box::into_raw(Box::new(AgentHandle {
        shutdown,
        thread: Some(thread),
        clear_socket_protector_on_stop: false,
        authentication_state,
    })) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_isRunning<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    if handle == 0 {
        return false;
    }

    let handle = unsafe { &*(handle as *const AgentHandle) };
    matches!(handle.thread.as_ref(), Some(thread) if !thread.is_finished())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_authenticationStatus<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return crate::authentication::AUTHENTICATION_UNCONFIRMED as jint;
    }

    let handle = unsafe { &*(handle as *const AgentHandle) };
    handle.authentication_state.status() as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_stop<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }

    let mut handle = unsafe { Box::from_raw(handle as *mut AgentHandle) };
    handle.shutdown.cancel();
    if let Some(thread) = handle.thread.take() {
        let _ = thread.join();
    }
    if handle.clear_socket_protector_on_stop {
        socket_protector::clear();
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_vpnDownloadBytes<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jlong {
    traffic_stats::download_bytes().min(jlong::MAX as u64) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_vpnUploadBytes<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jlong {
    traffic_stats::upload_bytes().min(jlong::MAX as u64) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_packetCaptureEnabled<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jboolean {
    packet_capture::is_enabled()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_setPacketCaptureEnabled<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    file: JString<'local>,
    enabled: jboolean,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        let path = PathBuf::from(file.try_to_string(env)?);
        match packet_capture::set_enabled(path, enabled) {
            Ok(()) => Ok(true),
            Err(error) => {
                throw(env, format!("failed to toggle packet capture: {error}"));
                Ok(false)
            }
        }
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_clearPacketCapture<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    file: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        let path = PathBuf::from(file.try_to_string(env)?);
        match packet_capture::clear(path) {
            Ok(()) => Ok(true),
            Err(error) => {
                throw(env, format!("failed to clear packet capture: {error}"));
                Ok(false)
            }
        }
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_packetCaptureReportJson<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    file: JString<'local>,
    limit: jint,
    proxy_listen_port: jint,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<jstring> {
        let path = PathBuf::from(file.try_to_string(env)?);
        let proxy_listen_port = u16::try_from(proxy_listen_port)
            .ok()
            .filter(|port| *port > 0);
        let json = packet_capture::report_json(
            &path,
            usize::try_from(limit.max(1)).unwrap_or(1),
            proxy_listen_port,
        )
        .unwrap_or_else(|error| format!("{{\"error\":{}}}", serde_json::Value::String(error)));
        Ok(env.new_string(json)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_dnsResolutionRecordsJson<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<jstring> {
        let json = traffic_stats::dns_resolution_records_json();
        Ok(env.new_string(json)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_httpProxyClientsJson<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    env.with_env(|env| -> jni::errors::Result<jstring> {
        Ok(env.new_string(http_proxy_clients_json())?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_blockHttpProxyClient<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    ip: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        let ip = ip.try_to_string(env)?;
        Ok(block_http_proxy_client(&ip))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_unblockHttpProxyClient<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    ip: JString<'local>,
) -> jboolean {
    env.with_env(|env| -> jni::errors::Result<jboolean> {
        let ip = ip.try_to_string(env)?;
        Ok(unblock_http_proxy_client(&ip))
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

fn throw(env: &mut Env<'_>, message: String) {
    let _ = env.throw_new(
        jni::jni_str!("java/lang/IllegalStateException"),
        JNIString::new(message),
    );
}

#[cfg(test)]
mod tests {
    use super::validate_key_pair;
    use protocol::RsaKeyPair;

    #[test]
    fn managed_key_pair_validation_rejects_mismatched_or_invalid_pem() {
        let first = RsaKeyPair::generate(2048).unwrap();
        let second = RsaKeyPair::generate(2048).unwrap();
        let first_private = first.private_key_to_pem().unwrap();
        let first_public = first.public_key_to_pem().unwrap();
        let second_public = second.public_key_to_pem().unwrap();

        assert!(validate_key_pair(&first_private, &first_public));
        assert!(!validate_key_pair(&first_private, &second_public));
        assert!(!validate_key_pair("not a private key", &first_public));
    }
}
