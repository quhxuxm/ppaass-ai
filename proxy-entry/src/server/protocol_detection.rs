use super::*;

pub async fn peek_connection_header(
    stream: &TcpStream,
    timeout: Duration,
) -> io::Result<Option<[u8; 4]>> {
    tokio::time::timeout(timeout, async {
        let mut header = [0u8; 4];
        loop {
            match stream.peek(&mut header).await {
                Ok(0) => return Ok(None),
                Ok(n) if n >= header.len() => return Ok(Some(header)),
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "入站连接首包超时")))
}

pub fn looks_like_yamux_header(header: &[u8; 4]) -> bool {
    let version = header[0];
    let frame_type = header[1];
    let flags = u16::from_be_bytes([header[2], header[3]]);

    version == 0 && frame_type <= 3 && (flags & !0x000f) == 0
}
