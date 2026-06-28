use std::net::SocketAddr;
use std::sync::Arc;

use fast_socks5::server::{
    NoAuthentication, Socks5ServerProtocol, SocksServerError,
    states::{CommandRead, Opened},
};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use protocol::{Address, TransportProtocol};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AndroidAgentError, Result};
use crate::http_proxy_clients::HttpProxyClientLease;
use crate::http_proxy_io::connect_direct_tcp;
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::yamux_session::{AndroidYamuxSessionManager, AndroidYamuxTargetStream};

pub async fn handle_socks5_connection(
    stream: TcpStream,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    client: HttpProxyClientLease,
) -> Result<()> {
    info!("Android SOCKS5 proxy connection");

    let protocol: Socks5ServerProtocol<TcpStream, Opened> = Socks5ServerProtocol::start(stream);
    let auth_state = protocol
        .negotiate_auth::<NoAuthentication>(&[NoAuthentication])
        .await
        .map_err(socks_error)?;
    let authenticated = Socks5ServerProtocol::finish_auth(auth_state);
    let (protocol, command, target_addr) = authenticated.read_command().await.map_err(socks_error)?;

    match command {
        Socks5Command::TCPConnect => {
            handle_tcp_connect(protocol, target_addr, sessions, direct_checker, client).await
        }
        Socks5Command::TCPBind | Socks5Command::UDPAssociate => {
            let _ = protocol.reply_error(&ReplyError::CommandNotSupported).await;
            Ok(())
        }
    }
}

async fn handle_tcp_connect(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    client: HttpProxyClientLease,
) -> Result<()> {
    let target_label = format_target_addr(&target_addr);
    let address = convert_target_addr(&target_addr);

    if direct_checker.is_direct(&address) {
        let target = address_to_string(&address);
        let mut target_stream = match connect_direct_tcp(&target).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("Android SOCKS5 direct connect failed {target}: {err}");
                let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
                return Err(AndroidAgentError::Connection(format!(
                    "SOCKS5 direct connect failed: {err}"
                )));
            }
        };

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut client_stream = protocol.reply_success(bind_addr).await.map_err(socks_error)?;
        let cancel = client.cancel_token();
        tokio::select! {
            result = relay_tcp_bidirectional(
                &mut client_stream,
                &mut target_stream,
                TcpRelayOptions::http_proxy(&target_label),
            ) => match result {
                Ok(stats) => debug!(
                    "Android SOCKS5 direct tunnel closed {target_label}: up={} down={}",
                    stats.client_to_remote, stats.remote_to_client
                ),
                Err(err) => debug!("Android SOCKS5 direct tunnel ended {target_label}: {err}"),
            },
            _ = cancel.cancelled() => {
                debug!("Android SOCKS5 direct tunnel cancelled {target_label}");
            }
        }
        return Ok(());
    }

    let mut connected_stream = match sessions
        .as_ref()
        .connect_to_target(address, TransportProtocol::Tcp)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            error!("Android SOCKS5 proxy stream failed {target_label}: {err}");
            let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
            return Err(err);
        }
    };

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut client_stream = protocol.reply_success(bind_addr).await.map_err(socks_error)?;
    relay_socks5_proxy(&mut client_stream, &mut connected_stream, &target_label, client).await
}

async fn relay_socks5_proxy(
    client_stream: &mut TcpStream,
    connected_stream: &mut AndroidYamuxTargetStream,
    target: &str,
    client: HttpProxyClientLease,
) -> Result<()> {
    let cancel = client.cancel_token();
    tokio::select! {
        result = relay_tcp_bidirectional(
            client_stream,
            connected_stream,
            TcpRelayOptions::http_proxy(target),
        ) => match result {
            Ok(stats) => debug!(
                "Android SOCKS5 proxy tunnel closed {target}: up={} down={}",
                stats.client_to_remote, stats.remote_to_client
            ),
            Err(err) => debug!("Android SOCKS5 proxy tunnel ended {target}: {err}"),
        },
        _ = cancel.cancelled() => {
            debug!("Android SOCKS5 proxy tunnel cancelled {target}");
        }
    }
    Ok(())
}

fn convert_target_addr(target: &TargetAddr) -> Address {
    match target {
        TargetAddr::Ip(addr) => match addr {
            SocketAddr::V4(v4) => Address::Ipv4 {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
            SocketAddr::V6(v6) => Address::Ipv6 {
                addr: v6.ip().octets(),
                port: v6.port(),
            },
        },
        TargetAddr::Domain(host, port) => Address::Domain {
            host: host.clone(),
            port: *port,
        },
    }
}

fn format_target_addr(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ip(addr) => addr.to_string(),
        TargetAddr::Domain(host, port) => format!("{host}:{port}"),
    }
}

fn socks_error(error: SocksServerError) -> AndroidAgentError {
    AndroidAgentError::Socks5(error.to_string())
}
