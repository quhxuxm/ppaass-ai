use desktop_agent_be::socks5_handler::resolve_udp_associate_reply_addr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn resolve_udp_reply_uses_control_ip_for_unspecified_bind_addr() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53000);
    let control_local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

    assert_eq!(
        reply_addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000)
    );
}

#[test]
fn resolve_udp_reply_keeps_specific_bind_addr() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 53000);
    let control_local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

    assert_eq!(reply_addr, bind_addr);
}

#[test]
fn resolve_udp_reply_uses_family_safe_fallback() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53000);
    let control_local_ip = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));

    let reply_addr = resolve_udp_associate_reply_addr(bind_addr, control_local_ip);

    assert_eq!(
        reply_addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000)
    );
}
