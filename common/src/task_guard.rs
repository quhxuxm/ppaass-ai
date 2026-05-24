use futures::FutureExt;
use std::any::Any;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe, PanicHookInfo};
use std::sync::Once;
use tokio::task::JoinHandle;
use tracing::{debug, error};

pub fn spawn_guarded<F>(task_name: &'static str, future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(payload) = AssertUnwindSafe(future).catch_unwind().await {
            error!(
                "后台任务 {task_name} panic，任务已隔离退出：{}",
                panic_payload_message(payload.as_ref())
            );
        }
    })
}

pub fn install_known_smoltcp_panic_hook() {
    static INSTALL: Once = Once::new();

    INSTALL.call_once(|| {
        let previous_hook = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if is_known_smoltcp_seq_underflow(info) {
                debug!(
                    "已抑制已知 smoltcp TCP 序列号下溢 panic：{}",
                    panic_payload_message(info.payload())
                );
                return;
            }
            previous_hook(info);
        }));
    });
}

fn is_known_smoltcp_seq_underflow(info: &PanicHookInfo<'_>) -> bool {
    let location_matches = info.location().is_some_and(|location| {
        let file = location.file();
        file.contains("smoltcp-0.12.0/src/wire/tcp.rs")
            || (file.contains("smoltcp") && file.ends_with("src/wire/tcp.rs"))
    });

    location_matches
        && panic_payload_message(info.payload())
            == "attempt to subtract sequence numbers with underflow"
}

pub fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_string()
}
