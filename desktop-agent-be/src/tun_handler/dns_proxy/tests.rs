use super::parser::{parse_dns_query, parse_dns_response};
use super::*;

#[test]
fn allocate_skips_pending_ids() {
    let mut pending = HashMap::new();
    pending.insert(
        0,
        PendingDnsRequest {
            client: "127.0.0.1:10000".parse().unwrap(),
            target: "10.10.10.2:53".parse().unwrap(),
            original_id: 42,
            query: "example.com".to_string(),
            record_type: "A".to_string(),
            started_at: Instant::now(),
            expires_at: Instant::now() + DNS_PENDING_TTL,
        },
    );
    let mut next_id = 0;

    assert_eq!(allocate_dns_id(&pending, &mut next_id), Some(1));
    assert_eq!(next_id, 2);
}

#[test]
fn rewrites_dns_transaction_id() {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00];
    assert_eq!(dns_id(&packet), Some(0x1234));

    write_dns_id(&mut packet, 0xabcd);
    assert_eq!(dns_id(&packet), Some(0xabcd));
    assert_eq!(&packet[2..], &[0x01, 0x00]);
}

#[test]
fn parses_dns_query_name_and_type() {
    let packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    assert_eq!(
        parse_dns_query(&packet),
        Some(("example.com".to_string(), "A".to_string()))
    );
}

#[test]
fn rejects_dns_response_as_query() {
    let packet = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
    ];

    assert_eq!(parse_dns_query(&packet), None);
}

#[test]
fn rejects_dns_query_with_trailing_bytes() {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    assert_eq!(parse_dns_query(&packet), None);
}

#[test]
fn parses_dns_response_answers() {
    let response = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
    ];

    let parsed = parse_dns_response(&response).unwrap();
    assert_eq!(parsed.status, "NOERROR");
    assert_eq!(parsed.answers, vec!["93.184.216.34"]);
    assert_eq!(parsed.min_ttl, Some(60));
}

#[test]
fn dns_response_cache_rewrites_transaction_id_on_hit() {
    let response = vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
    ];
    let summary = parse_dns_response(&response).unwrap();
    let mut cache = DnsResponseCache::default();

    cache.insert("Example.COM.", "a", &summary, &response);

    let cached = cache.get("example.com", "A", 0xabcd).unwrap();
    assert_eq!(dns_id(&cached), Some(0xabcd));
    assert_eq!(&cached[2..], &response[2..]);
}
