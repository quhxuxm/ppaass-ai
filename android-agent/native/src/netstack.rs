use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::ClientConnection;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};
use crate::fd_device::{AndroidTunDevice, RawFd};
use crate::udp_pool::UdpConnectionPool;

const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
const DNS_PROXY_CONNECTION_IDLE: Duration = Duration::from_secs(15);
const DNS_REQUEST_CHANNEL_SIZE: usize = 1024;
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);
const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_FLOW_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct ForwardContext {
    config: Arc<AndroidAgentConfig>,
    udp_pool: Arc<UdpConnectionPool>,
    tun_networks: TunNetworks,
    proxy_dns: bool,
}

type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

pub async fn run_android_agent(
    raw_fd: RawFd,
    config: AndroidAgentConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    config.validate()?;

    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.tun.ipv4)?;
    let ipv6 = config
        .tun
        .ipv6
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_cidr_v6)
        .transpose()?;
    let tun_networks = TunNetworks::new(ipv4, ipv4_prefix, ipv6);
    let mtu = config.tun.mtu as usize;
    let proxy_dns = config.tun.proxy_dns;
    let block_quic = config.tun.block_quic;

    info!(
        "starting Android TUN agent: ipv4={}, ipv6={:?}, mtu={}, proxy_dns={}, block_quic={}",
        config.tun.ipv4, config.tun.ipv6, mtu, proxy_dns, block_quic
    );

    let device = Arc::new(AndroidTunDevice::from_raw_fd(raw_fd)?);
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(mtu)
        .build()
        .map_err(|e| AndroidAgentError::Connection(format!("build netstack failed: {e}")))?;

    if let Some(runner) = runner {
        tokio::spawn(runner);
    }

    let tcp_listener = tcp_listener
        .ok_or_else(|| AndroidAgentError::Connection("netstack TCP listener unavailable".into()))?;
    let udp_socket = udp_socket
        .ok_or_else(|| AndroidAgentError::Connection("netstack UDP socket unavailable".into()))?;

    let (tun_to_stack, stack_to_tun) = spawn_packet_bridge(device, stack, mtu, shutdown.clone());
    let config = Arc::new(config);
    let udp_pool = UdpConnectionPool::new(config.clone());
    udp_pool.prewarm().await;
    let context = ForwardContext {
        config,
        udp_pool,
        tun_networks,
        proxy_dns,
    };

    let tcp_task = spawn_tcp_listener(tcp_listener, context.clone(), shutdown.clone());
    let udp_task = spawn_udp_sessions(udp_socket, context, block_quic, shutdown.clone());

    shutdown.cancelled().await;
    info!("Android TUN agent shutdown requested");
    let _ = tokio::join!(tun_to_stack, stack_to_tun, tcp_task, udp_task);
    info!("Android TUN agent stopped");
    Ok(())
}

fn spawn_packet_bridge(
    device: Arc<AndroidTunDevice>,
    stack: netstack_smoltcp::Stack,
    mtu: usize,
    shutdown: CancellationToken,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let (mut stack_sink, mut stack_stream) = stack.split();

    let input_device = device.clone();
    let input_shutdown = shutdown.clone();
    let tun_to_stack = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu.max(1500) + 64];
        loop {
            tokio::select! {
                _ = input_shutdown.cancelled() => break,
                read = input_device.recv(&mut buf) => {
                    match read {
                        Ok(n) if n > 0 => {
                            if let Err(e) = stack_sink.send(buf[..n].to_vec()).await {
                                warn!("failed to push packet into netstack: {e}");
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            warn!("failed to read Android VPN fd: {e}");
                            break;
                        }
                    }
                }
            }
        }
        debug!("android tun_to_stack task exited");
    });

    let output_shutdown = shutdown;
    let stack_to_tun = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = output_shutdown.cancelled() => break,
                packet = stack_stream.next() => {
                    match packet {
                        Some(Ok(packet)) => {
                            if let Err(e) = device.send(&packet).await {
                                warn!("failed to write packet to Android VPN fd: {e}");
                                break;
                            }
                        }
                        Some(Err(e)) => warn!("netstack stream error: {e}"),
                        None => break,
                    }
                }
            }
        }
        debug!("android stack_to_tun task exited");
    });

    (tun_to_stack, stack_to_tun)
}

fn spawn_tcp_listener(
    mut tcp_listener: netstack_smoltcp::TcpListener,
    context: ForwardContext,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = tcp_listener.next() => {
                    let Some((stream, source, target)) = accepted else { break };
                    let context = context.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_tcp(stream, source, target, context).await {
                            debug!("TUN TCP flow ended: {err}");
                        }
                    });
                }
            }
        }
        debug!("android TCP listener task exited");
    })
}

async fn handle_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: ForwardContext,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, context.proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("TCP", source, target, context.tun_networks)?;
    }

    debug!("Android TUN TCP proxy -> {}", target);
    let proxy = ClientConnection::connect(context.config.as_ref(), address, TransportProtocol::Tcp)
        .await
        .map_err(|e| AndroidAgentError::Connection(e.to_string()))?;
    let mut proxy_io = proxy.into_stream();
    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut proxy_io).await {
        debug!("Android TUN TCP proxy relay ended: {e}");
    }
    let _ = client.shutdown().await;
    Ok(())
}

fn spawn_udp_sessions(
    udp_socket: netstack_smoltcp::UdpSocket,
    context: ForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let dns_proxy = context
            .proxy_dns
            .then(|| DnsProxy::spawn(context.clone(), udp_tx.clone(), shutdown.clone()));
        let udp_relay = UdpRelay::spawn(context.clone(), udp_tx.clone(), shutdown.clone());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                message = udp_rx.next() => {
                    let Some((data, source, target)) = message else { break };
                    if context.proxy_dns && target.port() == 53 {
                        if let Some(dns_proxy) = &dns_proxy {
                            dns_proxy.send(source, target, data);
                        }
                        continue;
                    }

                    if context.tun_networks.is_ipv4_broadcast(target.ip()) {
                        debug!("Android TUN UDP broadcast dropped -> {}", target);
                        continue;
                    }
                    if let Err(e) = reject_tun_target("UDP", source, target, context.tun_networks)
                    {
                        debug!("Android TUN UDP target rejected: {e}");
                        continue;
                    }
                    if block_quic && target.port() == 443 {
                        debug!("Android TUN UDP/443 QUIC dropped -> {}", target);
                        continue;
                    }
                    udp_relay.send(source, target, data);
                }
            }
        }
        debug!("android UDP session task exited");
    })
}

struct DnsProxy {
    tx: mpsc::Sender<DnsProxyRequest>,
}

#[derive(Clone)]
struct DnsProxyRequest {
    client: SocketAddr,
    target: SocketAddr,
    packet: Vec<u8>,
}

struct PendingDnsRequest {
    client: SocketAddr,
    target: SocketAddr,
    original_id: u16,
    expires_at: Instant,
}

impl DnsProxy {
    fn spawn(
        context: ForwardContext,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(DNS_REQUEST_CHANNEL_SIZE);
        tokio::spawn(run_dns_proxy(context, netstack_tx, rx, shutdown));
        Arc::new(Self { tx })
    }

    fn send(&self, client: SocketAddr, target: SocketAddr, packet: Vec<u8>) {
        debug!(
            "Android TUN DNS request queued: {} -> {} bytes={}",
            client,
            target,
            packet.len()
        );
        match self.tx.try_send(DnsProxyRequest {
            client,
            target,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => debug!("Android TUN DNS queue is full; dropping packet"),
            Err(TrySendError::Closed(_)) => {
                debug!("Android TUN DNS proxy is closed; dropping packet");
            }
        }
    }
}

async fn run_dns_proxy(
    context: ForwardContext,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<DnsProxyRequest>,
    shutdown: CancellationToken,
) {
    let mut pending = HashMap::new();
    let mut next_id = 0u16;
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe_request = rx.recv() => {
                        let Some(request) = maybe_request else { break };
                        request
                    }
                }
            }
        };

        let connected = connect_dns_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN DNS proxy connection failed: {e}");
                android_log_error(format!("Android TUN DNS proxy connection failed: {e}"));
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("Android TUN DNS proxy connected");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(5));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_sleep = tokio::time::sleep(DNS_PROXY_CONNECTION_IDLE);
        tokio::pin!(idle_sleep);
        pending.clear();
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) =
                    send_dns_request(&mut writer, &mut pending, &mut next_id, &request).await
                {
                    debug!("Android TUN DNS proxy write failed: {e}");
                    retry_request = Some(request);
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle_sleep => {
                    debug!("Android TUN DNS proxy idle; closing connection");
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => cleanup_pending_dns(&mut pending),
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_dns_request(
                        &mut writer,
                        &mut pending,
                        &mut next_id,
                        &request,
                    ).await {
                        debug!("Android TUN DNS proxy write failed: {e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle_sleep.as_mut().reset(
                        tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE,
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("Android TUN DNS proxy closed");
                            break;
                        }
                        Ok(n) => {
                            let mut response = response_buf[..n].to_vec();
                            if let Err(e) = handle_dns_response(
                                &netstack_tx,
                                &mut pending,
                                &mut response,
                            ).await {
                                debug!("Android TUN DNS proxy response failed: {e}");
                            }
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE,
                            );
                        }
                        Err(e) => {
                            debug!("Android TUN DNS proxy read failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("Android TUN DNS proxy exited");
}

async fn connect_dns_stream(
    context: &ForwardContext,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    context
        .udp_pool
        .get_connected_stream(Address::ProxyDns { port: 53 }, TransportProtocol::Udp)
        .await
}

async fn send_dns_request<W>(
    writer: &mut W,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    next_id: &mut u16,
    request: &DnsProxyRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("Android TUN DNS request is too short; dropping");
        return Ok(());
    };

    cleanup_pending_dns(pending);
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("Android TUN DNS pending table is full; dropping request");
        return Ok(());
    };

    let mut packet = request.packet.clone();
    write_dns_id(&mut packet, upstream_id);
    pending.insert(
        upstream_id,
        PendingDnsRequest {
            client: request.client,
            target: request.target,
            original_id,
            expires_at: Instant::now() + DNS_PENDING_TTL,
        },
    );

    let write_result = async {
        writer.write_all(&packet).await?;
        writer.flush().await
    }
    .await;

    if write_result.is_err() {
        pending.remove(&upstream_id);
    }

    write_result
}

async fn handle_dns_response(
    netstack_tx: &UdpWriter,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    response: &mut [u8],
) -> io::Result<()> {
    let Some(upstream_id) = dns_id(response) else {
        debug!("Android TUN DNS response is too short; dropping");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("Android TUN DNS response had no matching id={upstream_id}");
        return Ok(());
    };

    write_dns_id(response, request.original_id);
    let mut tx = netstack_tx.lock().await;
    debug!(
        "Android TUN DNS response writeback: {} -> {} bytes={}",
        request.target,
        request.client,
        response.len()
    );
    tx.send((response.to_vec(), request.target, request.client))
        .await
}

fn cleanup_pending_dns(pending: &mut HashMap<u16, PendingDnsRequest>) {
    let now = Instant::now();
    pending.retain(|_, request| request.expires_at > now);
}

fn allocate_dns_id(pending: &HashMap<u16, PendingDnsRequest>, next_id: &mut u16) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

fn dns_id(packet: &[u8]) -> Option<u16> {
    let bytes = packet.get(..2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn write_dns_id(packet: &mut [u8], id: u16) {
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}

struct UdpRelay {
    tx: mpsc::Sender<UdpRelayRequest>,
}

#[derive(Clone)]
struct UdpRelayRequest {
    client: SocketAddr,
    target: SocketAddr,
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFlowKey {
    client: SocketAddr,
    target: SocketAddr,
}

struct UdpRelayState {
    flow_ids: HashMap<UdpFlowKey, u64>,
    flows: HashMap<u64, UdpFlowKey>,
    last_seen: HashMap<u64, Instant>,
    next_flow_id: u64,
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            last_seen: HashMap::new(),
            next_flow_id: 1,
        }
    }

    fn flow_id(&mut self, client: SocketAddr, target: SocketAddr) -> u64 {
        let key = UdpFlowKey { client, target };
        if let Some(id) = self.flow_ids.get(&key) {
            self.last_seen.insert(*id, Instant::now());
            return *id;
        }

        let id = self.next_available_flow_id();
        self.flow_ids.insert(key, id);
        self.flows.insert(id, key);
        self.last_seen.insert(id, Instant::now());
        id
    }

    fn flow(&self, flow_id: u64) -> Option<UdpFlowKey> {
        self.flows.get(&flow_id).copied()
    }

    fn next_available_flow_id(&mut self) -> u64 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
            if !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .last_seen
            .iter()
            .filter_map(|(id, last_seen)| ((*last_seen + UDP_FLOW_TTL) <= now).then_some(*id))
            .collect();

        for id in expired {
            self.last_seen.remove(&id);
            if let Some(key) = self.flows.remove(&id) {
                self.flow_ids.remove(&key);
            }
        }
    }
}

impl UdpRelay {
    fn spawn(
        context: ForwardContext,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(UDP_RELAY_CHANNEL_SIZE);
        tokio::spawn(run_udp_relay(context, netstack_tx, rx, shutdown));
        Arc::new(Self { tx })
    }

    fn send(&self, client: SocketAddr, target: SocketAddr, packet: Vec<u8>) {
        match self.tx.try_send(UdpRelayRequest {
            client,
            target,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                debug!("Android TUN UDP relay queue is full; dropping packet");
            }
            Err(TrySendError::Closed(_)) => {
                debug!("Android TUN UDP relay is closed; dropping packet");
            }
        }
    }
}

async fn run_udp_relay(
    context: ForwardContext,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<UdpRelayRequest>,
    shutdown: CancellationToken,
) {
    let mut state = UdpRelayState::new();
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe_request = rx.recv() => {
                        let Some(request) = maybe_request else { break };
                        request
                    }
                }
            }
        };

        let connected = connect_udp_relay_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN UDP relay connection failed: {e}");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("Android TUN UDP relay connected");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_sleep = tokio::time::sleep(UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle_sleep);
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) = send_udp_relay_request(&mut writer, &mut state, &request).await {
                    debug!("Android TUN UDP relay write failed: {e}");
                    retry_request = Some(request);
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle_sleep => {
                    debug!("Android TUN UDP relay idle; closing connection");
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => state.cleanup_expired(),
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_udp_relay_request(&mut writer, &mut state, &request).await {
                        debug!("Android TUN UDP relay write failed: {e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle_sleep.as_mut().reset(
                        tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("Android TUN UDP relay closed");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = handle_udp_relay_response(
                                &netstack_tx,
                                &state,
                                &response_buf[..n],
                            ).await {
                                debug!("Android TUN UDP relay response failed: {e}");
                            }
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                            );
                        }
                        Err(e) => {
                            debug!("Android TUN UDP relay read failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("Android TUN UDP relay exited");
}

async fn connect_udp_relay_stream(
    context: &ForwardContext,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    context
        .udp_pool
        .get_connected_stream(Address::UdpRelay, TransportProtocol::Udp)
        .await
}

async fn send_udp_relay_request<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    request: &UdpRelayRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let flow_id = state.flow_id(request.client, request.target);
    let packet = UdpRelayPacket {
        flow_id,
        address: socket_addr_to_address(request.target),
        data: request.packet.clone(),
    }
    .encode()
    .map_err(io::Error::other)?;

    writer.write_all(&packet).await?;
    writer.flush().await
}

async fn handle_udp_relay_response(
    netstack_tx: &UdpWriter,
    state: &UdpRelayState,
    response: &[u8],
) -> io::Result<()> {
    let packet = UdpRelayPacket::decode(response).map_err(io::Error::other)?;
    let Some(flow) = state.flow(packet.flow_id) else {
        debug!(
            "Android TUN UDP relay response had no matching flow id={}",
            packet.flow_id
        );
        return Ok(());
    };

    let mut tx = netstack_tx.lock().await;
    tx.send((packet.data, flow.target, flow.client)).await
}

#[derive(Clone, Copy)]
struct TunNetworks {
    ipv4: Ipv4Addr,
    ipv4_prefix: u8,
    ipv6: Option<(Ipv6Addr, u8)>,
}

impl TunNetworks {
    fn new(ipv4: Ipv4Addr, ipv4_prefix: u8, ipv6: Option<(Ipv6Addr, u8)>) -> Self {
        Self {
            ipv4,
            ipv4_prefix,
            ipv6,
        }
    }

    fn contains_ip(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => ipv4_in_cidr(ip, self.ipv4, self.ipv4_prefix),
            IpAddr::V6(ip) => self
                .ipv6
                .is_some_and(|(network, prefix)| ipv6_in_cidr(ip, network, prefix)),
        }
    }

    fn is_ipv4_broadcast(self, ip: IpAddr) -> bool {
        let IpAddr::V4(ip) = ip else {
            return false;
        };
        if self.ipv4_prefix >= 31 {
            return false;
        }
        let mask = ipv4_mask(self.ipv4_prefix);
        let network = u32::from(self.ipv4) & mask;
        let broadcast = network | !mask;
        u32::from(ip) == broadcast
    }
}

fn reject_tun_target(
    transport: &str,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
) -> Result<()> {
    if !tun_networks.contains_ip(target.ip()) {
        return Ok(());
    }

    Err(AndroidAgentError::Connection(format!(
        "TUN {transport} target loop detected: source={source}, target={target}"
    )))
}

fn address_for_tun_target(target: SocketAddr, proxy_dns: bool) -> (Address, bool) {
    if proxy_dns && target.port() == 53 {
        return (
            Address::ProxyDns {
                port: target.port(),
            },
            true,
        );
    }
    (socket_addr_to_address(target), false)
}

fn socket_addr_to_address(addr: SocketAddr) -> Address {
    match addr.ip() {
        IpAddr::V4(ip) => Address::Ipv4 {
            addr: ip.octets(),
            port: addr.port(),
        },
        IpAddr::V6(ip) => Address::Ipv6 {
            addr: ip.octets(),
            port: addr.port(),
        },
    }
}

fn parse_cidr_v4(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| AndroidAgentError::Connection(format!("invalid IPv4 CIDR: {value}")))?;
    let ip = ip
        .parse()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv4 address {ip}: {e}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv4 prefix: {e}")))?;
    if prefix > 32 {
        return Err(AndroidAgentError::Connection(
            "IPv4 prefix must be <= 32".to_string(),
        ));
    }
    Ok((ip, prefix))
}

fn parse_cidr_v6(value: &str) -> Result<(Ipv6Addr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| AndroidAgentError::Connection(format!("invalid IPv6 CIDR: {value}")))?;
    let ip = ip
        .parse()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv6 address {ip}: {e}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv6 prefix: {e}")))?;
    if prefix > 128 {
        return Err(AndroidAgentError::Connection(
            "IPv6 prefix must be <= 128".to_string(),
        ));
    }
    Ok((ip, prefix))
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = ipv4_mask(prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}

fn android_log_error(message: impl AsRef<str>) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;

        const ANDROID_LOG_ERROR: libc::c_int = 6;
        let text = message.as_ref().replace('\0', " ");
        let Ok(tag) = CString::new("PPAASS-Native") else {
            return;
        };
        let Ok(text) = CString::new(text) else {
            return;
        };
        unsafe {
            __android_log_write(ANDROID_LOG_ERROR, tag.as_ptr(), text.as_ptr());
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = message;
    }
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
}
