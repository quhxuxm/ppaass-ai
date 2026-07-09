//! DNS 协议解析辅助。
//!
//! agent 的 TUN UDP 入口需要判断一个 UDP/53 payload 是否真的是 DNS 查询。
//! 这里用成熟的 `hickory-proto` 做 DNS message 解码，避免靠端口或手写半包解析误判。

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

/// 已解析并规范化后的 DNS 查询问题段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    /// 查询域名，统一为小写并去掉末尾根点，根域名保留为 "."。
    pub query: String,
    /// 查询记录类型，例如 A、AAAA、HTTPS；未知类型用 TYPE<number> 表示。
    pub record_type: String,
}

/// 判断 UDP payload 是否是标准 DNS query。
///
/// 这里刻意只接受常规查询：QR 必须是 Query、OPCODE 必须是 QUERY、问题段必须只有
/// 一个，且 Answer/Authority 为空。Additional 允许存在，因为 EDNS(0) 的 OPT 记录
/// 会放在那里。解析完成后还要求没有尾随字节，避免“前缀像 DNS、后面夹杂其它数据”的
/// UDP/53 payload 被错误送进 DNS proxy。
pub fn parse_dns_query_packet(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < 12 {
        return None;
    }

    let mut decoder = BinDecoder::new(packet);
    let message = Message::read(&mut decoder).ok()?;
    if !decoder.is_empty()
        || message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
        || message.queries.len() != 1
        || !message.answers.is_empty()
        || !message.authorities.is_empty()
    {
        return None;
    }

    let query = message.queries.first()?;
    Some(DnsQuery {
        query: normalize_query_name(query.name().to_utf8()),
        record_type: record_type_name(query.query_type()),
    })
}

/// 轻量布尔判断，给 UDP 分流路径使用。
pub fn is_dns_query_packet(packet: &[u8]) -> bool {
    parse_dns_query_packet(packet).is_some()
}

fn normalize_query_name(name: String) -> String {
    let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        ".".to_string()
    } else {
        normalized
    }
}

fn record_type_name(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(code) => format!("TYPE{code}"),
        _ => record_type.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'E',
            b'x', b'A', b'm', b'P', b'l', b'E', 0x03, b'c', b'O', b'M', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn parses_standard_dns_query() {
        assert_eq!(
            parse_dns_query_packet(&example_query()),
            Some(DnsQuery {
                query: "example.com".to_string(),
                record_type: "A".to_string(),
            })
        );
    }

    #[test]
    fn rejects_dns_response_as_query() {
        let mut packet = example_query();
        packet[2] = 0x81;
        packet[3] = 0x80;

        assert_eq!(parse_dns_query_packet(&packet), None);
        assert!(!is_dns_query_packet(&packet));
    }

    #[test]
    fn rejects_query_with_multiple_questions() {
        let mut packet = example_query();
        packet[5] = 0x02;
        packet.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'n', b'e', b't', 0x00, 0x00,
            0x1c, 0x00, 0x01,
        ]);

        assert_eq!(parse_dns_query_packet(&packet), None);
    }

    #[test]
    fn rejects_query_with_trailing_bytes() {
        let mut packet = example_query();
        packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(parse_dns_query_packet(&packet), None);
    }
}
