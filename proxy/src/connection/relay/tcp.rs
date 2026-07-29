use super::*;

pub(super) async fn relay_tcp_with_half_close<T, A>(
    target_stream: &mut T,
    agent_io: &mut A,
    timeouts: TcpRelayTimeouts,
) -> io::Result<(u64, u64)>
where
    T: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // TCP relay 只保留这一套实现：始终使用明确的半关闭状态机。
    // 真正的字节搬运交给 Tokio copy_bidirectional；它的半关闭和双方向
    // 并发语义比手写 select 更稳定。外层 RelayCopyIo 只负责两件事：
    // 1. 记录读写活动，让 proxy 仍能执行“空闲超时”；
    // 2. 忽略无害的 shutdown 错误，避免请求方向 BrokenPipe 取消响应方向排空。
    //
    // 参数顺序使用 agent_io -> target_stream，因此返回值天然是：
    // agent->target 上行字节、target->agent 下行字节。
    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));
    let agent_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let target_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (activity_tx, mut activity_rx) = watch::channel(());
    let mut agent_copy_io = RelayCopyIo::new(
        agent_io,
        "agent->target",
        activity_tx.clone(),
        up_total.clone(),
        agent_eof.clone(),
    );
    let mut target_copy_io = RelayCopyIo::new(
        target_stream,
        "target->agent",
        activity_tx,
        down_total.clone(),
        target_eof.clone(),
    );

    let relay = tokio::io::copy_bidirectional_with_sizes(
        &mut agent_copy_io,
        &mut target_copy_io,
        common::TCP_RELAY_COPY_BUFFER_SIZE,
        common::TCP_RELAY_COPY_BUFFER_SIZE,
    );
    tokio::pin!(relay);

    loop {
        let half_closed = agent_eof.load(Ordering::Acquire) || target_eof.load(Ordering::Acquire);
        if let Some(timeout) = timeouts.current(half_closed) {
            let idle = tokio::time::sleep(timeout);
            tokio::pin!(idle);
            tokio::select! {
                result = &mut relay => return result,
                _ = &mut idle => {
                    if half_closed {
                        debug!("TCP 中继半关闭后空闲超过 {} 秒，关闭连接", timeout.as_secs());
                    } else {
                        debug!("TCP 中继空闲超过 {} 秒，关闭连接", timeout.as_secs());
                    }
                    return Ok((
                        up_total.load(Ordering::Acquire),
                        down_total.load(Ordering::Acquire),
                    ));
                }
                changed = activity_rx.changed() => {
                    if changed.is_err() {
                        // 两个方向都结束时 relay_directions 会先返回；这里保守地继续轮询，
                        // 避免 watch 发送端被提前 drop 时误判为空闲。
                        continue;
                    }
                }
            }
        } else {
            tokio::select! {
                result = &mut relay => return result,
                changed = activity_rx.changed() => {
                    if changed.is_err() {
                        continue;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TcpRelayTimeouts {
    idle: Option<Duration>,
    half_close_idle: Option<Duration>,
}

impl TcpRelayTimeouts {
    pub(super) fn new(idle_secs: u64, half_close_idle_secs: u64) -> Self {
        Self {
            idle: duration_from_secs(idle_secs),
            half_close_idle: duration_from_secs(half_close_idle_secs),
        }
    }

    #[cfg(test)]
    pub(super) fn from_durations(
        idle: Option<Duration>,
        half_close_idle: Option<Duration>,
    ) -> Self {
        Self {
            idle,
            half_close_idle,
        }
    }

    fn current(self, half_closed: bool) -> Option<Duration> {
        if !half_closed {
            return self.idle;
        }

        match (self.idle, self.half_close_idle) {
            (Some(idle), Some(half_close_idle)) => Some(idle.min(half_close_idle)),
            (Some(idle), None) => Some(idle),
            (None, Some(half_close_idle)) => Some(half_close_idle),
            (None, None) => None,
        }
    }
}

fn duration_from_secs(secs: u64) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

pub(super) fn can_ignore_tcp_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}
