use crate::connection_pool::ConnectionPool;
use anyhow::{Result, anyhow};
use fast_socks5::server::{DnsResolveHelper, Socks5ServerProtocol, SocksServerError};
use fast_socks5::server::states;
use fast_socks5::{ReplyError, Socks5Command};
use fast_socks5::util::target_addr::TargetAddr;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error};

/// Handle an already-accepted SOCKS5 connection
pub async fn handle_connection(stream: TcpStream, pool: Arc<ConnectionPool>) -> Result<()> {
    let (
        protocol,
        command,
        target_addr,
    ): (
        Socks5ServerProtocol<TcpStream, states::CommandRead>,
        Socks5Command,
        TargetAddr,
    ) = Socks5ServerProtocol::accept_no_auth(stream)
        .await
        .map_err(map_socks_error)?
        .read_command()
        .await
        .map_err(map_socks_error)?
        .resolve_dns()
        .await
        .map_err(map_socks_error)?;

    match command {
        Socks5Command::TCPConnect => {
            debug!("SOCKS5 CONNECT request to {}", target_addr);
            let (target_host, target_port) = target_addr.into_string_and_port();
            let reply_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let mut client_stream = protocol
                .reply_success(reply_addr)
                .await
                .map_err(map_socks_error)?;
            relay_proxy_stream(&mut client_stream, pool, target_host, target_port).await
        }
        _ => {
            if let Err(err) = protocol.reply_error(&ReplyError::CommandNotSupported).await {
                error!("Failed to reply unsupported command error: {err:?}");
            }
            Err(anyhow!("SOCKS5 command {:?} not supported", command))
        }
    }
}

async fn relay_proxy_stream(
    client_stream: &mut TcpStream,
    pool: Arc<ConnectionPool>,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    debug!(
        "Establishing relay through proxy to {}:{}",
        target_host, target_port
    );

    let conn = pool.get_connection().await?;
    let mut buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            result = client_stream.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        debug!("Client closed SOCKS5 tunnel");
                        break;
                    }
                    Ok(n) => {
                        let response = conn
                            .send_data(
                                &buf[..n],
                                Some(target_host.clone()),
                                Some(target_port)
                            )
                            .await?;

                        if !response.is_empty() {
                            client_stream.write_all(&response).await?;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from SOCKS5 client: {e}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn map_socks_error(err: SocksServerError) -> anyhow::Error {
    anyhow!(err)
}
