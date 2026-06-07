//! netstack supervisor。
//!
//! TUN 模式依赖用户态协议栈把 IP 包还原成 TCP/UDP 流。这里把一组相关任务
//! 作为一个 generation 管理：runner、TUN<->stack 包桥、TCP listener、UDP sessions。
//! 任一关键任务退出都会取消整组并重建，提升 TUN 模式长期运行的恢复能力。

use super::*;

struct NetstackGeneration {
    // generation id 只用于日志，方便判断是否经历过重建。
    id: u64,
    // 子 token 用于停止当前 generation，不影响父级 TUN shutdown token。
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
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
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

    Ok(spawn_guarded("desktop netstack supervisor", async move {
        run_netstack_supervisor(device, mtu, context, block_quic, shutdown, initial).await;
    }))
}

fn start_netstack_generation(
    id: u64,
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
    block_quic: bool,
    parent_shutdown: &CancellationToken,
) -> Result<NetstackGeneration> {
    // 每次 generation 都重新构建 StackBuilder，避免复用已经异常退出的内部状态。
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(mtu)
        .build()
        .map_err(|e| AgentError::Connection(format!("构建 netstack 失败：{e}")))?;
    let runner = runner.ok_or_else(|| AgentError::Connection("netstack runner 不可用".into()))?;
    let tcp_listener =
        tcp_listener.ok_or_else(|| AgentError::Connection("netstack TCP 监听器不可用".into()))?;
    let udp_socket =
        udp_socket.ok_or_else(|| AgentError::Connection("netstack UDP 套接字不可用".into()))?;

    let generation_shutdown = parent_shutdown.child_token();
    let (tun_to_stack, stack_to_tun) =
        spawn_packet_bridge(device, stack, mtu, generation_shutdown.clone());
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
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
    mut generation: NetstackGeneration,
) {
    let mut next_generation_id = generation.id + 1;
    let mut restart_delay = Duration::from_millis(200);

    loop {
        // 等待任一关键任务退出；只要不是外部 shutdown，就整体重建 generation。
        let stopped_task = tokio::select! {
            _ = shutdown.cancelled() => {
                None
            }
            result = &mut generation.runner => {
                match result {
                    Ok(NetstackRunnerExit::Finished) => warn!("netstack runner generation={} 已退出，准备重建 netstack", generation.id),
                    Ok(NetstackRunnerExit::Error(err)) => warn!("netstack runner generation={} 错误退出：{err}，准备重建 netstack", generation.id),
                    Ok(NetstackRunnerExit::Panic(message)) => warn!("netstack runner generation={} panic：{message}，准备重建 netstack", generation.id),
                    Err(err) => warn!("netstack runner generation={} join 错误：{err}，准备重建 netstack", generation.id),
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

        // 一个任务退出时，其余同 generation 任务也必须停止，否则会继续持有旧 stack 资源。
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
                    info!("netstack 已重建：generation={}", next_generation_id);
                    generation = next;
                    next_generation_id += 1;
                    restart_delay = Duration::from_millis(200);
                    break;
                }
                Err(err) => {
                    warn!("重建 netstack 失败：{err}");
                    restart_delay = (restart_delay * 2).min(Duration::from_secs(5));
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(restart_delay) => {}
                    }
                }
            }
        }
    }

    debug!("netstack supervisor 退出");
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
        Ok(()) => warn!("netstack {task_name} generation={generation} 已退出，准备重建 netstack"),
        Err(err) => warn!(
            "netstack {task_name} generation={generation} join 错误：{err}，准备重建 netstack"
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
        Err(err) => warn!("中止 netstack generation 任务 {name} 时出现 join 错误：{err}"),
    }
}

pub(super) async fn wait_tun_task(name: &'static str, mut handle: JoinHandle<()>) {
    tokio::select! {
        result = &mut handle => {
            if let Err(e) = result {
                warn!("TUN 任务 {name} 异常结束：{e}");
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(3)) => {
            warn!("TUN 任务 {name} 未及时退出，正在中止任务");
            handle.abort();
            let _ = handle.await;
        }
    }
}
