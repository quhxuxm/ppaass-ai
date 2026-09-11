/// Extracts the first DNS server name from a TLS ClientHello record.
///
/// The parser accepts a record that ends immediately after the complete SNI
/// extension even when the surrounding TLS record has not arrived in full.
/// This lets TUN clients recover a hostname from a bounded prefetch without
/// waiting for the rest of a large ClientHello.
pub fn tls_client_hello_server_name(packet: &[u8]) -> Option<String> {
    let record = packet.get(0..5)?;
    if record[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let record_end = 5 + record_len;
    let handshake = packet.get(5..record_end).unwrap_or(packet.get(5..)?);
    if handshake.first().copied()? != 1 {
        return None;
    }
    handshake.get(1..4)?;
    let hello = handshake.get(4..)?;
    let mut offset = 34;
    let session_id_len = *hello.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_len = u16::from_be_bytes([*hello.get(offset)?, *hello.get(offset + 1)?]) as usize;
    offset += 2 + cipher_len;
    let compression_len = *hello.get(offset)? as usize;
    offset += 1 + compression_len;
    let extensions_len =
        u16::from_be_bytes([*hello.get(offset)?, *hello.get(offset + 1)?]) as usize;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?.min(hello.len());
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let extension_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        offset += 4;
        let extension = hello.get(offset..offset.checked_add(extension_len)?)?;
        offset += extension_len;
        if extension_type != 0 || extension.len() < 5 {
            continue;
        }
        let names_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
        let mut name_offset: usize = 2;
        let names_end = name_offset.checked_add(names_len)?;
        while name_offset + 3 <= names_end && names_end <= extension.len() {
            let name_type = extension[name_offset];
            let name_len =
                u16::from_be_bytes([extension[name_offset + 1], extension[name_offset + 2]])
                    as usize;
            name_offset += 3;
            let name = std::str::from_utf8(
                extension.get(name_offset..name_offset.checked_add(name_len)?)?,
            )
            .ok()?;
            name_offset += name_len;
            if name_type == 0 && !name.is_empty() {
                return Some(name.trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    None
}
