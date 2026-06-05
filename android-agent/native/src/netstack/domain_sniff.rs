pub(super) fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?.min(buf.len());
    let data = buf.get(5..record_end)?;

    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let mut p = 4usize;

    if data.len() < p + 2 + 32 {
        return None;
    }
    p += 2 + 32;

    let sid_len = *data.get(p)? as usize;
    p += 1;
    p = p.checked_add(sid_len)?;

    if data.len() < p + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
    p += 2;
    p = p.checked_add(cs_len)?;

    let cm_len = *data.get(p)? as usize;
    p += 1;
    p = p.checked_add(cm_len)?;

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
            if elen < 2 {
                return None;
            }
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
                    return (!trimmed.is_empty()).then_some(trimmed);
                }
                q = name_end;
            }
            return None;
        }

        p = ext_payload_end;
    }

    None
}

pub(super) fn extract_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let headers = &text[..header_end];
    let mut lines = headers.split("\r\n");

    let first = lines.next()?;
    if !first.contains(" HTTP/") {
        return None;
    }

    for line in lines {
        let mut parts = line.splitn(2, ':');
        let name = parts.next()?.trim();
        let value = parts.next()?.trim();
        if name.eq_ignore_ascii_case("Host") {
            let host = if let Some(stripped) = value.strip_prefix('[') {
                stripped.split(']').next()?
            } else {
                value.split(':').next()?
            };
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            return (!host.is_empty()).then_some(host);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();
        let name_len = name.len() as u16;

        let mut entry = Vec::new();
        entry.push(0u8);
        entry.extend_from_slice(&name_len.to_be_bytes());
        entry.extend_from_slice(name);

        let mut sn_ext = Vec::new();
        sn_ext.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        sn_ext.extend_from_slice(&entry);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sn_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn_ext);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&0u16.to_be_bytes());
        hello.push(0);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let hs_len = hello.len() as u32;
        let mut handshake = vec![
            0x01,
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let rec_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let buf = build_client_hello("WWW.Example.COM.");
        assert_eq!(extract_tls_sni(&buf).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn extracts_http_host() {
        let req = b"GET / HTTP/1.1\r\nhost: Example.COM:8080\r\n\r\n";
        assert_eq!(extract_http_host(req).as_deref(), Some("example.com"));
    }
}
