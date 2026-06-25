use jni::objects::{JClass, JObject, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{Env, EnvUnowned};
use tokio_util::sync::CancellationToken;

use crate::config::AndroidAgentConfig;
use crate::fd_device::RawFd;
use crate::http_proxy::run_android_http_proxy;
use crate::netstack::run_android_agent;
use crate::socket_protector;
use crate::traffic_stats;

struct AgentHandle {
    shutdown: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
    clear_socket_protector_on_stop: bool,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_start<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    vpn_service: JObject<'local>,
) -> jlong {
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
                    eprintln!("failed to create Tokio runtime: {err}");
                    return;
                }
            };

            if let Err(err) = runtime.block_on(run_android_agent(raw_fd, config, task_shutdown)) {
                eprintln!("Android agent stopped with error: {err}");
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
    })) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_startHttpProxy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    listen_port: jint,
) -> jlong {
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
                    eprintln!("failed to create HTTP proxy Tokio runtime: {err}");
                    return;
                }
            };

            if let Err(err) = runtime.block_on(run_android_http_proxy(config, port, task_shutdown))
            {
                eprintln!("Android HTTP proxy stopped with error: {err}");
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

fn throw(env: &mut Env<'_>, message: String) {
    let _ = env.throw_new(
        jni::jni_str!("java/lang/IllegalStateException"),
        JNIString::new(message),
    );
}
