use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong};
use tokio_util::sync::CancellationToken;

use crate::config::AndroidAgentConfig;
use crate::fd_device::RawFd;
use crate::netstack::run_android_agent;

struct AgentHandle {
    shutdown: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_start(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) -> jlong {
    let json: String = match env.get_string(&config_json) {
        Ok(value) => value.into(),
        Err(err) => {
            throw(&mut env, format!("failed to read config JSON: {err}"));
            return 0;
        }
    };

    let config: AndroidAgentConfig = match serde_json::from_str(&json) {
        Ok(config) => config,
        Err(err) => {
            throw(&mut env, format!("invalid config JSON: {err}"));
            return 0;
        }
    };

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
            throw(
                &mut env,
                format!("failed to spawn native agent thread: {err}"),
            );
            return 0;
        }
    };

    Box::into_raw(Box::new(AgentHandle {
        shutdown,
        thread: Some(thread),
    })) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_ppaass_ai_agent_NativeAgent_stop(
    _env: JNIEnv,
    _class: JClass,
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
}

fn throw(env: &mut JNIEnv, message: String) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}
