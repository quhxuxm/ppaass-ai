//! 在 TUN TCP 流首段字节中嗅探目标域名，用于补充 DNS 缓存未命中时的直连判定。
//!
//! 现代浏览器经常使用 DoH/DoT 或系统 DNS 缓存，DNS 查询并不一定经过 agent 的
//! `DnsProxy`，因此 `DirectDomainCache` 中可能查不到 IP -> 域名映射。
//! 直接从 TLS ClientHello 的 SNI 扩展或 HTTP Host 头中解析域名，可以让
//! `direct_access` 中的域名规则在 TUN 模式下稳定生效。

/// 从 TLS ClientHello 中提取 SNI 字段中的主机名。
///
/// 缓冲区中通常会包含一个完整的 TLS Record（不超过 16KB），
/// 这里手工解析协议字段，避免引入额外依赖。
pub(super) fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS Record header: type(1)=22(handshake), version(2), length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?.min(buf.len());
    let data = buf.get(5..record_end)?;

    // Handshake header: type(1)=1(ClientHello), length(3)
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let mut p = 4usize;

    // ClientHello: version(2), random(32)
    if data.len() < p + 2 + 32 {
        return None;
    }
    p += 2 + 32;

    // session_id (1 byte length + payload)
    let sid_len = *data.get(p)? as usize;
    p += 1;
    p = p.checked_add(sid_len)?;

    // cipher_suites (2 byte length + payload)
    if data.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    p = p.checked_add(cs_len)?;

    // compression_methods (1 byte length + payload)
    let cm_len = *data.get(p)? as usize;
    p += 1;
    p = p.checked_add(cm_len)?;

    // extensions (2 byte length + payload)
    if data.len() < p + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    let ext_end = p.checked_add(ext_total)?.min(data.len());

    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([data[p], data[p + 1]]);
        let elen = u16::from_be_bytes([data[p + 2], data[p + 3]]) as usize;
        p += 4;
        let ext_payload_end = p.checked_add(elen)?;
        if ext_payload_end > ext_end {
            return None;
        }

        if etype == 0x0000 {
            // server_name extension
            // list_len(2), entries: name_type(1)=0 + name_len(2) + name
            if elen < 2 {
                return None;
            }
            let _list_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
            let mut q = p + 2;
            while q + 3 <= ext_payload_end {
                let ntype = data[q];
                let nlen = u16::from_be_bytes([data[q + 1], data[q + 2]]) as usize;
                q += 3;
                let name_end = q.checked_add(nlen)?;
                if name_end > ext_payload_end {
                    return None;
                }
                if ntype == 0 {
                    let name = std::str::from_utf8(&data[q..name_end]).ok()?;
                    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
                    if trimmed.is_empty() {
                        return None;
                    }
                    return Some(trimmed);
                }
                q = name_end;
            }
            return None;
        }

        p = ext_payload_end;
    }

    None
}

/// 从 HTTP/1.x 请求头中提取 Host 字段，忽略端口号和首尾空白。
///
/// 调用方需要保证缓冲区中至少包含完整的请求头；若数据不足，
/// 函数会返回 `None`，调用方可以选择继续读取或放弃嗅探。
pub(super) fn extract_http_host(buf: &[u8]) -> Option<String> {
    // 必须能看到请求行末尾（CRLF），否则直接放弃避免误判。
    let text = std::str::from_utf8(buf).ok()?;
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let headers = &text[..header_end];
    let mut lines = headers.split("\r\n");

    // 第一行必须形如 "METHOD path HTTP/x.y"，避免把 TLS 字节误当 HTTP。
    let first = lines.next()?;
    if !first.contains(" HTTP/") {
        return None;
    }

    for line in lines {
        let mut parts = line.splitn(2, ':');
        let name = parts.next()?.trim();
        let value = parts.next()?.trim();
        if name.eq_ignore_ascii_case("Host") {
            // Host 可能带端口号；IPv6 字面量会被方括号包裹。
            let host = if let Some(stripped) = value.strip_prefix('[') {
                stripped.split(']').next()?
            } else {
                value.split(':').next()?
            };
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() {
                return None;
            }
            return Some(host);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(server_name: &str) -> Vec<u8> {
        // Minimal valid TLS 1.2 ClientHello with a single server_name extension.
        let name = server_name.as_bytes();
        let name_len = name.len() as u16;

        // server_name entry: type(1)=0 + name_len(2) + name
        let mut entry = Vec::new();
        entry.push(0u8);
        entry.extend_from_slice(&name_len.to_be_bytes());
        entry.extend_from_slice(name);
        // server_name_list: list_len(2) + entry
        let mut sn_ext = Vec::new();
        sn_ext.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        sn_ext.extend_from_slice(&entry);
        // extension: type(2)=0 + length(2) + payload
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sn_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn_ext);
        let extensions = ext;

        // ClientHello body
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id length
        hello.extend_from_slice(&0u16.to_be_bytes()); // cipher_suites length
        hello.push(0); // compression_methods length
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Handshake header
        let hs_len = hello.len() as u32;
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        // TLS Record header
        let rec_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // version
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extract_sni_from_minimal_client_hello() {
        let buf = build_client_hello("www.example.com");
        assert_eq!(extract_tls_sni(&buf).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn extract_sni_lowercases_and_strips_trailing_dot() {
        let buf = build_client_hello("WWW.Example.COM.");
        assert_eq!(extract_tls_sni(&buf).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn extract_sni_returns_none_for_non_tls_buffer() {
        assert!(extract_tls_sni(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").is_none());
    }

    #[test]
    fn extract_sni_handles_truncated_buffer() {
        let buf = build_client_hello("www.example.com");
        assert!(extract_tls_sni(&buf[..10]).is_none());
    }

    #[test]
    fn extract_host_simple_get() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn extract_host_strips_port_and_lowercases() {
        let req = b"GET / HTTP/1.1\r\nhost: Example.COM:8080\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn extract_host_handles_ipv6_brackets() {
        let req = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("::1"));
    }

    #[test]
    fn extract_host_rejects_non_http_buffer() {
        let buf = build_client_hello("www.example.com");
        assert!(extract_http_host(&buf).is_none());
    }
}

