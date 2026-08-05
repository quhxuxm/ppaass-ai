use tracing::{debug, warn};

pub(super) fn prune_finished_stream_tasks(tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    tasks.retain(|task| !task.is_finished());
}

pub(super) async fn abort_stream_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    if tasks.is_empty() {
        return;
    }

    warn!(
        "Yamux session 结束时仍有 {} 个活跃子 stream，正在关闭；这些请求的上层 HTTP body 可能被截断",
        tasks.len()
    );
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        match task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => debug!("Yamux 子 stream 任务回收时返回错误：{err}"),
        }
    }
}
