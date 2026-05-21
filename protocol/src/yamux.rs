use crate::message::{ConnectRequest, ConnectResponse, MAX_YAMUX_CONTROL_FRAME_SIZE};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_yamux_connect_request<W>(
    writer: &mut W,
    request: &ConnectRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_control_frame(writer, &bitcode::serialize(request).map_err(invalid_data)?).await
}

pub async fn read_yamux_connect_request<R>(reader: &mut R) -> io::Result<ConnectRequest>
where
    R: AsyncRead + Unpin,
{
    let frame = read_control_frame(reader).await?;
    bitcode::deserialize(&frame).map_err(invalid_data)
}

pub async fn write_yamux_connect_response<W>(
    writer: &mut W,
    response: &ConnectResponse,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_control_frame(writer, &bitcode::serialize(response).map_err(invalid_data)?).await
}

pub async fn read_yamux_connect_response<R>(reader: &mut R) -> io::Result<ConnectResponse>
where
    R: AsyncRead + Unpin,
{
    let frame = read_control_frame(reader).await?;
    bitcode::deserialize(&frame).map_err(invalid_data)
}

async fn write_control_frame<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_YAMUX_CONTROL_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Yamux control frame too large: {} > {}",
                payload.len(),
                MAX_YAMUX_CONTROL_FRAME_SIZE
            ),
        ));
    }

    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn read_control_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let frame_len = reader.read_u32().await? as usize;
    if frame_len > MAX_YAMUX_CONTROL_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Yamux control frame too large: {frame_len} > {MAX_YAMUX_CONTROL_FRAME_SIZE}"),
        ));
    }

    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

fn invalid_data(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}
