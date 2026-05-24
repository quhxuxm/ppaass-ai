use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use common::{install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded};
use futures::FutureExt;
use netstack_smoltcp::StackBuilder;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::ForwardContext;
use super::bridge::spawn_packet_bridge;
use super::tcp::spawn_tcp_listener;
use super::udp::spawn_udp_sessions;
use crate::error::{AndroidAgentError, Result};
use crate::fd_device::AndroidTunDevice;

struct NetstackGeneration {
    id: u64,
    shutdown: CancellationToken,
    runner: JoinHandle<NetstackRunnerExit>,
    tun_to_stack: JoinHandle<()>,
    stack_to_tun: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
    udp_task: JoinHandle<()>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NetstackTaskKind {
    Runner,
    TunToStack,
    StackToTun,
    TcpListener,
    UdpSessions,
}

enum NetstackRunnerExit {
    Finished,
    Error(String),
    Panic(String),
}

pub(super) fn spawn_netstack_supervisor(
    device: Arc<AndroidTunDevice>,
    mtu: usize,
    context: ForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
) -> Result<JoinHandle<()>> {
    install_known_smoltcp_panic_hook();
    let initial = start_netstack_generation(
        0,
        device.clone(),
        mtu,
        context.clone(),
        block_quic,
        &shutdown,
    )?;

    Ok(spawn_guarded("android netstack supervisor", async move {
        run_netstack_supervisor(device, mtu, context, block_quic, shutdown, initial).await;
    }))
}

fn start_netstack_generation(
    id: u64,
    device: Arc<AndroidTunDevice>,
    mtu: usize,
    context: ForwardContext,
    block_quic: bool,
    parent_shutdown: &CancellationToken,
) -> Result<NetstackGeneration> {
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(mtu)
        .build()
        .map_err(|e| AndroidAgentError::Connection(format!("build netstack failed: {e}")))?;
    let runner = runner
        .ok_or_else(|| AndroidAgentError::Connection("netstack runner unavailable".into()))?;
    let tcp_listener = tcp_listener
        .ok_or_else(|| AndroidAgentError::Connection("netstack TCP listener unavailable".into()))?;
    let udp_socket = udp_socket
        .ok_or_else(|| AndroidAgentError::Connection("netstack UDP socket unavailable".into()))?;

    let generation_shutdown = parent_shutdown.child_token();
    let (tun_to_stack, stack_to_tun) = spawn_packet_bridge(
        device,
        stack,
        mtu,
        generation_shutdown.clone(),
        parent_shutdown.clone(),
    );
    let tcp_task = spawn_tcp_listener(tcp_listener, context.clone(), generation_shutdown.clone());
    let udp_task = spawn_udp_sessions(udp_socket, context, block_quic, generation_shutdown.clone());

    Ok(NetstackGeneration {
        id,
        shutdown: generation_shutdown,
        runner: spawn_netstack_runner(runner),
        tun_to_stack,
        stack_to_tun,
        tcp_task,
        udp_task,
    })
}

async fn run_netstack_supervisor(
    device: Arc<AndroidTunDevice>,
    mtu: usize,
    context: ForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
    mut generation: NetstackGeneration,
) {
    let mut next_generation_id = generation.id + 1;
    let mut restart_delay = Duration::from_millis(200);

    loop {
        let stopped_task = tokio::select! {
            _ = shutdown.cancelled() => None,
            result = &mut generation.runner => {
                match result {
                    Ok(NetstackRunnerExit::Finished) => warn!("Android netstack runner generation={} exited; rebuilding netstack", generation.id),
                    Ok(NetstackRunnerExit::Error(err)) => warn!("Android netstack runner generation={} failed: {err}; rebuilding netstack", generation.id),
                    Ok(NetstackRunnerExit::Panic(message)) => warn!("Android netstack runner generation={} panicked: {message}; rebuilding netstack", generation.id),
                    Err(err) => warn!("Android netstack runner generation={} join error: {err}; rebuilding netstack", generation.id),
                }
                Some(NetstackTaskKind::Runner)
            }
            result = &mut generation.tun_to_stack => {
                log_netstack_task_exit("tun_to_stack", generation.id, result);
                Some(NetstackTaskKind::TunToStack)
            }
            result = &mut generation.stack_to_tun => {
                log_netstack_task_exit("stack_to_tun", generation.id, result);
                Some(NetstackTaskKind::StackToTun)
            }
            result = &mut generation.tcp_task => {
                log_netstack_task_exit("tcp_task", generation.id, result);
                Some(NetstackTaskKind::TcpListener)
            }
            result = &mut generation.udp_task => {
                log_netstack_task_exit("udp_task", generation.id, result);
                Some(NetstackTaskKind::UdpSessions)
            }
        };

        let Some(stopped_task) = stopped_task else {
            stop_netstack_generation(generation, None).await;
            break;
        };

        stop_netstack_generation(generation, Some(stopped_task)).await;
        if shutdown.is_cancelled() {
            break;
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(restart_delay) => {}
        }
        if shutdown.is_cancelled() {
            break;
        }

        loop {
            match start_netstack_generation(
                next_generation_id,
                device.clone(),
                mtu,
                context.clone(),
                block_quic,
                &shutdown,
            ) {
                Ok(next) => {
                    info!("Android netstack rebuilt: generation={next_generation_id}");
                    generation = next;
                    next_generation_id += 1;
                    restart_delay = Duration::from_millis(200);
                    break;
                }
                Err(err) => {
                    warn!("failed to rebuild Android netstack: {err}");
                    restart_delay = (restart_delay * 2).min(Duration::from_secs(5));
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(restart_delay) => {}
                    }
                }
            }
        }
    }

    debug!("Android netstack supervisor exited");
}

fn spawn_netstack_runner(runner: netstack_smoltcp::Runner) -> JoinHandle<NetstackRunnerExit> {
    tokio::spawn(async move {
        match AssertUnwindSafe(runner).catch_unwind().await {
            Ok(Ok(())) => NetstackRunnerExit::Finished,
            Ok(Err(e)) => NetstackRunnerExit::Error(e.to_string()),
            Err(payload) => NetstackRunnerExit::Panic(panic_payload_message(payload.as_ref())),
        }
    })
}

fn log_netstack_task_exit(
    task_name: &'static str,
    generation: u64,
    result: std::result::Result<(), tokio::task::JoinError>,
) {
    match result {
        Ok(()) => warn!(
            "Android netstack {task_name} generation={generation} exited; rebuilding netstack"
        ),
        Err(err) => warn!(
            "Android netstack {task_name} generation={generation} join error: {err}; rebuilding netstack"
        ),
    }
}

async fn stop_netstack_generation(
    generation: NetstackGeneration,
    completed: Option<NetstackTaskKind>,
) {
    generation.shutdown.cancel();

    if completed != Some(NetstackTaskKind::Runner) {
        abort_generation_task("netstack_runner", generation.runner).await;
    }
    if completed != Some(NetstackTaskKind::TunToStack) {
        abort_generation_task("tun_to_stack", generation.tun_to_stack).await;
    }
    if completed != Some(NetstackTaskKind::StackToTun) {
        abort_generation_task("stack_to_tun", generation.stack_to_tun).await;
    }
    if completed != Some(NetstackTaskKind::TcpListener) {
        abort_generation_task("tcp_task", generation.tcp_task).await;
    }
    if completed != Some(NetstackTaskKind::UdpSessions) {
        abort_generation_task("udp_task", generation.udp_task).await;
    }
}

async fn abort_generation_task<T>(name: &'static str, handle: JoinHandle<T>)
where
    T: Send + 'static,
{
    handle.abort();
    match handle.await {
        Ok(_) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) => warn!("error while aborting Android netstack generation task {name}: {err}"),
    }
}
