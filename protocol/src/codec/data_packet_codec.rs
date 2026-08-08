use crate::message::DataPacket;
use std::io;

const HEADER_LEN: usize = 3;

pub(super) fn encode(packet: DataPacket) -> io::Result<Vec<u8>> {
    let stream_id = packet.stream_id.as_bytes();
    let stream_id_len = u16::try_from(stream_id.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TCP stream ID is too long"))?;
    let header_len = HEADER_LEN + stream_id.len();
    let data_len = packet.data.len();
    let mut payload = packet.data;
    payload.reserve(header_len);
    payload.resize(header_len + data_len, 0);
    payload.copy_within(0..data_len, header_len);
    payload[0] = u8::from(packet.is_end);
    payload[1..HEADER_LEN].copy_from_slice(&stream_id_len.to_be_bytes());
    payload[HEADER_LEN..header_len].copy_from_slice(stream_id);
    Ok(payload)
}

pub(super) fn decode(mut payload: Vec<u8>) -> io::Result<DataPacket> {
    if payload.len() < HEADER_LEN || payload[0] > 1 {
        return Err(invalid_packet());
    }
    let is_end = payload[0] == 1;
    let stream_id_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    let header_len = HEADER_LEN
        .checked_add(stream_id_len)
        .filter(|length| *length <= payload.len())
        .ok_or_else(invalid_packet)?;
    let stream_id = std::str::from_utf8(&payload[HEADER_LEN..header_len])
        .map_err(|_| invalid_packet())?
        .to_owned();
    let data_len = payload.len() - header_len;
    payload.copy_within(header_len.., 0);
    payload.truncate(data_len);
    Ok(DataPacket {
        stream_id,
        data: payload,
        is_end,
    })
}

fn invalid_packet() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid TCP data packet")
}
