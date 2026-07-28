//! 使用 proxy 配置的上游 DNS 显式解析目标域名。
//!
//! 这里不使用系统 resolver：DNS 上游本身必须是数字 IP，查询经由 `EgressState`
//! 创建的出站 UDP socket 发出，因而也会遵循 `outbound_interface` 配置。

use super::EgressState;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const DNS_PORT: u16 = 53;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_RESPONSE_MAX_SIZE: usize = u16::MAX as usize;

pub(super) struct ExplicitDnsResolver {
    upstream: SocketAddr,
    timeout: Duration,
}

impl ExplicitDnsResolver {
    pub(super) fn from_config(value: Option<&str>) -> io::Result<Option<Self>> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };

        let upstream = parse_upstream(value)?;
        tracing::info!(%upstream, "已启用显式 DNS 解析");
        Ok(Some(Self {
            upstream,
            timeout: DNS_QUERY_TIMEOUT,
        }))
    }

    #[cfg(test)]
    fn with_timeout(upstream: SocketAddr, timeout: Duration) -> Self {
        Self { upstream, timeout }
    }

    pub(super) async fn resolve(
        &self,
        egress_state: &EgressState,
        host: &str,
        port: u16,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut name = Name::from_ascii(host).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标域名 {host:?} 无效：{err}"),
            )
        })?;
        // DNS wire format always terminates the name at the root. Marking the request name as
        // fully qualified keeps response question validation semantically exact.
        name.set_fqdn(true);

        // A 与 AAAA 独立查询；任一地址族成功即可继续连接，避免单栈网络因另一族查询
        // 失败而完全不可用。
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.query(egress_state, &name, RecordType::A),
            self.query(egress_state, &name, RecordType::AAAA),
        );

        let mut addresses = Vec::new();
        let mut last_error = None;
        for result in [ipv4_result, ipv6_result] {
            match result {
                Ok(ips) => {
                    for ip in ips {
                        let address = SocketAddr::new(ip, port);
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Err(err) => last_error = Some(err),
            }
        }

        if !addresses.is_empty() {
            tracing::debug!(
                domain = %host,
                %port,
                upstream = %self.upstream,
                resolved = ?addresses,
                "显式 DNS 解析完成"
            );
            return Ok(addresses);
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("显式 DNS 未解析到 {host} 的 A 或 AAAA 地址"),
            )
        }))
    }

    async fn query(
        &self,
        egress_state: &EgressState,
        name: &Name,
        record_type: RecordType,
    ) -> io::Result<Vec<IpAddr>> {
        let query_id = rand::random::<u16>();
        let mut query = Message::new(query_id, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name.clone(), record_type));
        let payload = query.to_vec().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("编码 DNS {record_type} 查询失败：{err}"),
            )
        })?;

        let exchange = async {
            let socket = egress_state
                .connect_udp_resolved_addr(self.upstream)
                .await?;
            let sent = socket.send(&payload).await?;
            if sent != payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("DNS 查询只发送了 {sent}/{} 字节", payload.len()),
                ));
            }

            let mut response = vec![0_u8; DNS_RESPONSE_MAX_SIZE];
            let received = socket.recv(&mut response).await?;
            response.truncate(received);
            parse_response(&response, query_id, name, record_type)
        };

        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "通过 {} 查询 {} {} 超时（{}ms）",
                        self.upstream,
                        name,
                        record_type,
                        self.timeout.as_millis()
                    ),
                )
            })?
    }
}

fn parse_upstream(value: &str) -> io::Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }

    let unbracketed = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("dns_upstream_addr 必须是数字 IP 或 IP:端口，不能依赖系统 DNS 解析：{value:?}"),
    ))
}

fn parse_response(
    packet: &[u8],
    query_id: u16,
    name: &Name,
    record_type: RecordType,
) -> io::Result<Vec<IpAddr>> {
    let mut decoder = BinDecoder::new(packet);
    let response = Message::read(&mut decoder).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("解码 DNS {record_type} 响应失败：{err}"),
        )
    })?;
    if !decoder.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS 响应包含尾随数据",
        ));
    }
    if response.metadata.id != query_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "DNS 响应事务 ID 不匹配：期望 {query_id}，收到 {}",
                response.metadata.id
            ),
        ));
    }
    if response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS 上游返回的报文不是标准查询响应",
        ));
    }
    if response.metadata.truncation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS UDP 响应被截断，拒绝使用不完整结果",
        ));
    }
    if response.queries.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DNS 响应问题段数量不是 1：{}", response.queries.len()),
        ));
    }
    let response_query = &response.queries[0];
    if response_query.name() != name
        || response_query.query_type() != record_type
        || response_query.query_class() != DNSClass::IN
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS 响应问题段与请求不匹配",
        ));
    }
    match response.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS 上游报告域名 {name} 不存在"),
            ));
        }
        response_code => {
            return Err(io::Error::other(format!(
                "DNS 上游查询 {name} {record_type} 失败：{response_code}"
            )));
        }
    }

    let mut addresses = Vec::new();
    for answer in &response.answers {
        let ip = match &answer.data {
            RData::A(address) if record_type == RecordType::A => Some(IpAddr::V4(address.0)),
            RData::AAAA(address) if record_type == RecordType::AAAA => Some(IpAddr::V6(address.0)),
            _ => None,
        };
        if let Some(ip) = ip
            && !addresses.contains(&ip)
        {
            addresses.push(ip);
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        Record,
        rdata::{A, AAAA},
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::net::{TcpListener, UdpSocket};

    #[test]
    fn parses_numeric_upstreams_without_system_dns() {
        assert_eq!(
            parse_upstream("223.5.5.5").unwrap(),
            "223.5.5.5:53".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("[2001:4860:4860::8888]").unwrap(),
            "[2001:4860:4860::8888]:53".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("[2001:4860:4860::8888]:5353").unwrap(),
            "[2001:4860:4860::8888]:5353".parse().unwrap()
        );
        assert_eq!(
            parse_upstream("resolver.example:53").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn validates_dns_response_identity_and_question() {
        let name = Name::from_ascii("example.test").unwrap();
        let packet = response_packet(41, &name, RecordType::A);
        assert_eq!(
            parse_response(&packet, 42, &name, RecordType::A)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let other_name = Name::from_ascii("other.test").unwrap();
        assert_eq!(
            parse_response(&packet, 41, &other_name, RecordType::A)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn configured_resolver_connects_domain_using_explicit_upstream() {
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_upstream = dns_socket.local_addr().unwrap();
        let dns_task = tokio::spawn(serve_two_queries(dns_socket));

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let egress = EgressState::new(None, Some(&dns_upstream.to_string())).unwrap();

        let target = format!("only-explicit.invalid:{target_port}");
        tokio::time::timeout(Duration::from_secs(5), egress.connect_tcp(&target))
            .await
            .expect("显式 DNS 连接不应挂起")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), target_listener.accept())
            .await
            .expect("目标 listener 应收到显式解析后的连接")
            .unwrap();
        dns_task.await.unwrap();
    }

    #[tokio::test]
    async fn numeric_target_bypasses_explicit_resolver() {
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_upstream = dns_socket.local_addr().unwrap();
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let egress = EgressState::new(None, Some(&dns_upstream.to_string())).unwrap();

        let target = target_addr.to_string();
        let connect = egress.connect_tcp(&target);
        let (stream, accepted) = tokio::join!(connect, target_listener.accept());
        stream.unwrap();
        accepted.unwrap();

        let mut packet = [0_u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), dns_socket.recv_from(&mut packet))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn explicit_query_has_a_bounded_timeout() {
        let dns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = ExplicitDnsResolver::with_timeout(
            dns_socket.local_addr().unwrap(),
            Duration::from_millis(25),
        );
        let egress = EgressState::new(None, None).unwrap();
        let name = Name::from_ascii("timeout.invalid").unwrap();

        assert_eq!(
            resolver
                .query(&egress, &name, RecordType::A)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    async fn serve_two_queries(socket: UdpSocket) {
        for _ in 0..2 {
            let mut packet = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
            let query = Message::from_vec(&packet[..length]).unwrap();
            let question = query.queries.first().unwrap().clone();
            let mut response =
                Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            response.add_query(question.clone());
            match question.query_type() {
                RecordType::A => {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
                RecordType::AAAA => {
                    // 返回一个不可连接的文档地址会拖慢聚焦测试，因此只验证空 AAAA
                    // 响应与有效 A 结果可以组合。
                }
                _ => unreachable!(),
            }
            let response = response.to_vec().unwrap();
            socket.send_to(&response, peer).await.unwrap();
        }
    }

    fn response_packet(query_id: u16, name: &Name, record_type: RecordType) -> Vec<u8> {
        let mut response = Message::new(query_id, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(name.clone(), record_type));
        match record_type {
            RecordType::A => {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
            }
            RecordType::AAAA => {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    60,
                    RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                ));
            }
            _ => unreachable!(),
        }
        response.to_vec().unwrap()
    }
}
