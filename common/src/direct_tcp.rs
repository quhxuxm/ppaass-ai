use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{Instant, Sleep, timeout};

/// IPv6/IPv4 直连候选之间的启动间隔。
///
/// 第一个候选仍会立即发起；如果它没有快速成功，另一个地址族无需等待系统级
/// TCP connect 超时就能开始尝试。
const DIRECT_TCP_FALLBACK_DELAY: Duration = Duration::from_millis(250);
const DIRECT_TCP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

type ConnectAttempt = Pin<Box<dyn Future<Output = (SocketAddr, io::Result<TcpStream>)> + Send>>;

/// 解析目标并用 Happy Eyeballs 风格的交错竞速建立 TCP 直连。
///
/// `configure` 会在每个候选 socket 上、connect 之前调用，供 Android 执行
/// `VpnService.protect()`，也可用于设置平台 socket 参数。
pub async fn connect_tcp_happy_eyeballs<F>(target: &str, configure: F) -> io::Result<TcpStream>
where
    F: Fn(&Socket, SocketAddr) -> io::Result<()> + Clone + Send + 'static,
{
    let addresses = tokio::net::lookup_host(target).await?.collect::<Vec<_>>();
    connect_tcp_addresses_happy_eyeballs(addresses, configure).await
}

pub async fn connect_tcp_addresses_happy_eyeballs<F>(
    addresses: Vec<SocketAddr>,
    configure: F,
) -> io::Result<TcpStream>
where
    F: Fn(&Socket, SocketAddr) -> io::Result<()> + Clone + Send + 'static,
{
    let mut candidates = interleave_address_families(addresses).into_iter();
    let Some(first) = candidates.next() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no target address resolved",
        ));
    };

    let mut attempts = FuturesUnordered::<ConnectAttempt>::new();
    push_attempt(&mut attempts, first, configure.clone());
    let fallback = tokio::time::sleep(DIRECT_TCP_FALLBACK_DELAY);
    tokio::pin!(fallback);
    let mut has_more_candidates = candidates.len() > 0;
    let mut last_error = None;

    loop {
        tokio::select! {
            result = attempts.next() => {
                let Some((address, result)) = result else {
                    break;
                };
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => {
                        last_error = Some(io::Error::new(
                            error.kind(),
                            format!("direct TCP connect {address} failed: {error}"),
                        ));
                        // 快速失败时不人为等待 250ms；立即尝试下一个候选。
                        if attempts.is_empty()
                            && let Some(next) = candidates.next()
                        {
                            push_attempt(&mut attempts, next, configure.clone());
                            reset_fallback(&mut fallback);
                            has_more_candidates = candidates.len() > 0;
                        }
                    }
                }
            }
            _ = &mut fallback, if has_more_candidates => {
                if let Some(next) = candidates.next() {
                    push_attempt(&mut attempts, next, configure.clone());
                    reset_fallback(&mut fallback);
                }
                has_more_candidates = candidates.len() > 0;
            }
        }

        if attempts.is_empty() && !has_more_candidates {
            break;
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no target address could be connected",
        )
    }))
}

fn push_attempt<F>(
    attempts: &mut FuturesUnordered<ConnectAttempt>,
    address: SocketAddr,
    configure: F,
) where
    F: Fn(&Socket, SocketAddr) -> io::Result<()> + Send + 'static,
{
    attempts.push(Box::pin(async move {
        let result = connect_one(address, configure).await;
        (address, result)
    }));
}

async fn connect_one<F>(target: SocketAddr, configure: F) -> io::Result<TcpStream>
where
    F: Fn(&Socket, SocketAddr) -> io::Result<()>,
{
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    configure(&socket, target)?;
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    timeout(DIRECT_TCP_ATTEMPT_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("direct TCP connect {target} timed out"),
            )
        })?
}

fn reset_fallback(fallback: &mut Pin<&mut Sleep>) {
    fallback
        .as_mut()
        .reset(Instant::now() + DIRECT_TCP_FALLBACK_DELAY);
}

/// 保留 DNS 对每个地址族给出的顺序，同时让 IPv6/IPv4 候选交替出现。
pub fn interleave_address_families(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first_family) = addresses.first().map(|address| address.ip()) else {
        return Vec::new();
    };
    let first_is_ipv6 = matches!(first_family, IpAddr::V6(_));
    let mut seen = HashSet::with_capacity(addresses.len());
    let mut ipv6 = VecDeque::new();
    let mut ipv4 = VecDeque::new();
    for address in addresses {
        if !seen.insert(address) {
            continue;
        }
        if address.is_ipv6() {
            ipv6.push_back(address);
        } else {
            ipv4.push_back(address);
        }
    }
    let mut ordered = Vec::with_capacity(ipv6.len() + ipv4.len());

    while !ipv6.is_empty() || !ipv4.is_empty() {
        let (first, second) = if first_is_ipv6 {
            (&mut ipv6, &mut ipv4)
        } else {
            (&mut ipv4, &mut ipv6)
        };
        if let Some(address) = first.pop_front() {
            ordered.push(address);
        }
        if let Some(address) = second.pop_front() {
            ordered.push(address);
        }
    }

    ordered
}
