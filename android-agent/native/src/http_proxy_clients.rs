use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use serde_json::json;
use tokio_util::sync::CancellationToken;

static HTTP_PROXY_CLIENTS: OnceLock<HttpProxyClientRegistry> = OnceLock::new();

struct HttpProxyClientRegistry {
    next_id: AtomicU64,
    active: DashMap<u64, Arc<HttpProxyClient>>,
    blocked: DashMap<IpAddr, ()>,
}

struct HttpProxyClient {
    id: u64,
    peer_addr: SocketAddr,
    ip: IpAddr,
    cancel: CancellationToken,
    leases: AtomicUsize,
}

pub(crate) struct HttpProxyClientLease {
    client: Arc<HttpProxyClient>,
}

impl HttpProxyClientRegistry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            active: DashMap::new(),
            blocked: DashMap::new(),
        }
    }

    fn register(&self, peer_addr: SocketAddr) -> HttpProxyClientLease {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let client = Arc::new(HttpProxyClient {
            id,
            peer_addr,
            ip: peer_addr.ip(),
            cancel: CancellationToken::new(),
            leases: AtomicUsize::new(1),
        });
        self.active.insert(id, client.clone());
        HttpProxyClientLease { client }
    }

    fn is_blocked(&self, ip: IpAddr) -> bool {
        self.blocked.contains_key(&ip)
    }

    fn block(&self, ip: IpAddr) {
        self.blocked.insert(ip, ());
        self.cancel_ip(ip);
    }

    fn unblock(&self, ip: IpAddr) {
        self.blocked.remove(&ip);
    }

    fn cancel_ip(&self, ip: IpAddr) {
        for entry in self.active.iter() {
            if entry.value().ip == ip {
                entry.value().cancel.cancel();
            }
        }
    }

    fn remove_active(&self, id: u64) {
        self.active.remove(&id);
    }
}

impl HttpProxyClientLease {
    pub(crate) fn clone_lease(&self) -> Self {
        self.client.leases.fetch_add(1, Ordering::Relaxed);
        Self {
            client: self.client.clone(),
        }
    }

    pub(crate) fn cancel_token(&self) -> CancellationToken {
        self.client.cancel.clone()
    }
}

impl Drop for HttpProxyClientLease {
    fn drop(&mut self) {
        if self.client.leases.fetch_sub(1, Ordering::AcqRel) == 1 {
            http_proxy_client_registry().remove_active(self.client.id);
        }
    }
}

fn http_proxy_client_registry() -> &'static HttpProxyClientRegistry {
    HTTP_PROXY_CLIENTS.get_or_init(HttpProxyClientRegistry::new)
}

// 连接登记只按客户端 IP 聚合；局域网客户端通常会为同一个浏览器打开多个 TCP 连接。
pub(crate) fn register_http_proxy_client(peer_addr: SocketAddr) -> HttpProxyClientLease {
    http_proxy_client_registry().register(peer_addr)
}

pub(crate) fn is_http_proxy_client_blocked(ip: IpAddr) -> bool {
    http_proxy_client_registry().is_blocked(ip)
}

pub(crate) fn http_proxy_clients_json() -> String {
    let registry = http_proxy_client_registry();
    let mut active_by_ip: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in registry.active.iter() {
        let client = entry.value();
        active_by_ip
            .entry(client.ip.to_string())
            .or_default()
            .push(client.peer_addr.to_string());
    }

    let active = active_by_ip
        .into_iter()
        .map(|(ip, mut peers)| {
            peers.sort();
            json!({
                "ip": ip,
                "connections": peers.len(),
                "peers": peers,
                "blocked": registry.is_blocked(
                    ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                ),
            })
        })
        .collect::<Vec<_>>();

    let mut blocked = registry
        .blocked
        .iter()
        .map(|entry| entry.key().to_string())
        .collect::<Vec<_>>();
    blocked.sort();

    json!({
        "active": active,
        "blocked": blocked,
    })
    .to_string()
}

pub(crate) fn block_http_proxy_client(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    http_proxy_client_registry().block(ip);
    true
}

pub(crate) fn unblock_http_proxy_client(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    http_proxy_client_registry().unblock(ip);
    true
}
