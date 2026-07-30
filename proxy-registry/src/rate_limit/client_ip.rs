use super::*;

pub(super) fn resolve_client_ip(
    trust_proxy_headers: bool,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<IpAddr> {
    let peer_ip = peer.map(|peer| normalize_ip(peer.ip()));
    if trust_proxy_headers && peer_ip.is_some_and(|ip| ip.is_loopback()) {
        forwarded_for(headers).or(peer_ip)
    } else {
        peer_ip
    }
}

fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .rfind(|value| !value.is_empty())
        .and_then(parse_forwarded_ip)
        .or_else(|| {
            headers
                .get(header::FORWARDED)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit(',').next())
                .and_then(|hop| {
                    hop.split(';').find_map(|parameter| {
                        let (name, value) = parameter.trim().split_once('=')?;
                        name.eq_ignore_ascii_case("for")
                            .then_some(value.trim().trim_matches('"'))
                    })
                })
                .and_then(parse_forwarded_ip)
        })
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|value| value.split_once(']'))
                .and_then(|(ip, _)| ip.parse::<IpAddr>().ok())
        })
        .map(normalize_ip)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
