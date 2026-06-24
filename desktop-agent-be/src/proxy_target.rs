//! 显式 HTTP/SOCKS 代理目标的本地解析辅助。
//!
//! TUN 模式天然拿到的是浏览器/系统已经解析后的目标 IP；而 HTTP CONNECT 和
//! SOCKS5 Domain 目标通常只把域名交给 agent。如果直接把域名发给 proxy，proxy
//! 端会重新 DNS，视频 CDN 可能落到另一个边缘节点，表现为分片完整但下载很慢。
//! 这里用 agent 本机系统 DNS 做一次短超时解析，尽量让显式代理入口也连接到
//! 和本机浏览器更接近的 CDN IP；解析失败则回退域名，保持兼容性。

use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::error::Result;
use dashmap::DashMap;
use protocol::{Address, TransportProtocol};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tracing::debug;

/// 显式代理域名目标的本地 DNS 超时。
///
/// 这个解析发生在本地代理握手之后、连接 proxy 目标之前。时间不能太长，否则会把
/// 每个视频分片的建连路径拖慢；但也要给系统 DNS 缓存/解析器一个短窗口。
const LOCAL_PROXY_DNS_TIMEOUT: Duration = Duration::from_millis(300);
/// 视频分片会反复访问同一批 CDN host；本地缓存避免每条分片连接都触发系统 DNS。
const LOCAL_PROXY_DNS_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
struct CachedProxyDns {
    addr: SocketAddr,
    expires_at: Instant,
}

static LOCAL_PROXY_DNS_CACHE: OnceLock<DashMap<String, CachedProxyDns>> = OnceLock::new();

pub(crate) async fn get_proxy_tcp_stream_with_local_dns_fallback(
    pool: &ConnectionPool,
    address: Address,
    protocol: &'static str,
    label: &str,
) -> Result<ConnectedStream> {
    let resolved = resolve_proxy_domain_locally(address, protocol, label).await;
    match pool
        .get_connected_stream(resolved.address.clone(), TransportProtocol::Tcp)
        .await
    {
        Ok(stream) => Ok(stream),
        Err(first_err) => {
            let Some(fallback) = resolved.fallback else {
                return Err(first_err);
            };
            debug!("{protocol} 本地 DNS 目标连接失败，回退原始域名目标：{label} error={first_err}");
            pool.get_connected_stream(fallback, TransportProtocol::Tcp)
                .await
        }
    }
}

struct ResolvedProxyTarget {
    address: Address,
    fallback: Option<Address>,
}

async fn resolve_proxy_domain_locally(
    address: Address,
    protocol: &'static str,
    label: &str,
) -> ResolvedProxyTarget {
    let Address::Domain { host, port } = address else {
        return ResolvedProxyTarget {
            address,
            fallback: None,
        };
    };
    let original = Address::Domain {
        host: host.clone(),
        port,
    };
    let cache_key = format!("{}:{port}", host.to_ascii_lowercase());
    if let Some(cached) = local_proxy_dns_cache().get(&cache_key)
        && cached.expires_at > Instant::now()
    {
        let addr = cached.addr;
        debug!("{protocol} 本地 DNS 缓存命中代理目标：{label} -> {addr}");
        return ResolvedProxyTarget {
            address: socket_addr_to_address(addr),
            fallback: Some(original),
        };
    }

    let lookup =
        tokio::time::timeout(LOCAL_PROXY_DNS_TIMEOUT, lookup_host((host.as_str(), port))).await;

    match lookup {
        Ok(Ok(addrs)) => {
            let Some(addr) = addrs.into_iter().next() else {
                debug!("{protocol} 本地 DNS 无结果，继续使用域名目标：{label}");
                return ResolvedProxyTarget {
                    address: original,
                    fallback: None,
                };
            };
            local_proxy_dns_cache().insert(
                cache_key,
                CachedProxyDns {
                    addr,
                    expires_at: Instant::now() + LOCAL_PROXY_DNS_CACHE_TTL,
                },
            );
            let resolved = socket_addr_to_address(addr);
            debug!("{protocol} 本地 DNS 解析代理目标：{label} -> {addr}");
            ResolvedProxyTarget {
                address: resolved,
                fallback: Some(original),
            }
        }
        Ok(Err(err)) => {
            debug!("{protocol} 本地 DNS 解析失败，继续使用域名目标：{label} error={err}");
            ResolvedProxyTarget {
                address: original,
                fallback: None,
            }
        }
        Err(_) => {
            debug!(
                "{protocol} 本地 DNS 解析超过 {}ms，继续使用域名目标：{label}",
                LOCAL_PROXY_DNS_TIMEOUT.as_millis()
            );
            ResolvedProxyTarget {
                address: original,
                fallback: None,
            }
        }
    }
}

fn local_proxy_dns_cache() -> &'static DashMap<String, CachedProxyDns> {
    LOCAL_PROXY_DNS_CACHE.get_or_init(DashMap::new)
}

fn socket_addr_to_address(addr: SocketAddr) -> Address {
    match addr {
        SocketAddr::V4(v4) => Address::Ipv4 {
            addr: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => Address::Ipv6 {
            addr: v6.ip().octets(),
            port: v6.port(),
        },
    }
}
