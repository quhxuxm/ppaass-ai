use anyhow::{Context, Result};
use std::net::SocketAddr;

pub(super) async fn serve_public_and_control(
    public_listener: tokio::net::TcpListener,
    public_app: axum::Router,
    control_listener: tokio::net::TcpListener,
    control_app: axum::Router,
) -> Result<()> {
    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let public_shutdown = shutdown_receiver.clone();
    let control_shutdown = shutdown_receiver;
    let mut public_task = tokio::spawn(async move {
        axum::serve(
            public_listener,
            public_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(public_shutdown))
        .await
    });
    let mut control_task = tokio::spawn(async move {
        axum::serve(control_listener, control_app)
            .with_graceful_shutdown(wait_for_shutdown(control_shutdown))
            .await
    });

    tokio::select! {
        result = &mut public_task => {
            shutdown_sender.send_replace(true);
            result.context("公开 Registry 服务任务异常退出")??;
            control_task.await.context("控制面服务任务异常退出")??;
        }
        result = &mut control_task => {
            shutdown_sender.send_replace(true);
            result.context("控制面服务任务异常退出")??;
            public_task.await.context("公开 Registry 服务任务异常退出")??;
        }
        _ = shutdown_signal() => {
            shutdown_sender.send_replace(true);
            public_task.await.context("公开 Registry 服务任务异常退出")??;
            control_task.await.context("控制面服务任务异常退出")??;
        }
    }
    Ok(())
}

async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "监听 Ctrl-C 失败");
    }
}
