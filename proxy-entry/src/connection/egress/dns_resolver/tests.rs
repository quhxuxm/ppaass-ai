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
        let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
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
