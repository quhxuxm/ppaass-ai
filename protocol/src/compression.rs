use flate2::Compression as GzipLevel;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::str::FromStr;

use crate::message::MAX_MESSAGE_SIZE;

/// agent 与 proxy 之间数据传输的压缩模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CompressionMode {
    /// 不压缩
    #[default]
    None,
    /// Zstandard 压缩 - 速度与压缩率较均衡
    Zstd,
    /// LZ4 压缩 - 速度最快，压缩率较低
    Lz4,
    /// Gzip 压缩 - 兼容性广，速度较慢
    Gzip,
}

impl CompressionMode {
    /// 从 u8 标志获取压缩模式
    pub fn from_flag(flag: u8) -> Self {
        match flag {
            1 => CompressionMode::Zstd,
            2 => CompressionMode::Lz4,
            3 => CompressionMode::Gzip,
            _ => CompressionMode::None,
        }
    }

    /// 转换为协议消息使用的 u8 标志
    pub fn to_flag(self) -> u8 {
        match self {
            CompressionMode::None => 0,
            CompressionMode::Zstd => 1,
            CompressionMode::Lz4 => 2,
            CompressionMode::Gzip => 3,
        }
    }
}

impl FromStr for CompressionMode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "zstd" | "zstandard" => CompressionMode::Zstd,
            "lz4" => CompressionMode::Lz4,
            "gzip" | "gz" => CompressionMode::Gzip,
            _ => CompressionMode::None,
        })
    }
}

impl std::fmt::Display for CompressionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionMode::None => write!(f, "none"),
            CompressionMode::Zstd => write!(f, "zstd"),
            CompressionMode::Lz4 => write!(f, "lz4"),
            CompressionMode::Gzip => write!(f, "gzip"),
        }
    }
}

/// 使用指定压缩模式压缩数据
pub fn compress(data: &[u8], mode: CompressionMode) -> io::Result<Vec<u8>> {
    match mode {
        CompressionMode::None => Ok(data.to_vec()),
        CompressionMode::Zstd => compress_zstd(data),
        CompressionMode::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        CompressionMode::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), GzipLevel::fast());
            encoder.write_all(data)?;
            encoder.finish()
        }
    }
}

/// 使用指定压缩模式解压数据
pub fn decompress(data: &[u8], mode: CompressionMode) -> io::Result<Vec<u8>> {
    let decompressed = match mode {
        CompressionMode::None => {
            ensure_decompressed_size(data.len())?;
            data.to_vec()
        }
        CompressionMode::Zstd => decompress_zstd(data, MAX_MESSAGE_SIZE)?,
        CompressionMode::Lz4 => decompress_lz4(data, MAX_MESSAGE_SIZE)?,
        CompressionMode::Gzip => decompress_gzip(data, MAX_MESSAGE_SIZE)?,
    };
    ensure_decompressed_size(decompressed.len())?;
    Ok(decompressed)
}

#[cfg(feature = "zstd-compression")]
fn compress_zstd(data: &[u8]) -> io::Result<Vec<u8>> {
    zstd::encode_all(data, 3)
}

#[cfg(not(feature = "zstd-compression"))]
fn compress_zstd(_data: &[u8]) -> io::Result<Vec<u8>> {
    Err(zstd_feature_disabled_error())
}

#[cfg(feature = "zstd-compression")]
fn decompress_zstd(data: &[u8], max_size: usize) -> io::Result<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(data)?;
    read_limited(decoder, max_size)
}

#[cfg(not(feature = "zstd-compression"))]
fn decompress_zstd(_data: &[u8], _max_size: usize) -> io::Result<Vec<u8>> {
    Err(zstd_feature_disabled_error())
}

#[cfg(not(feature = "zstd-compression"))]
fn zstd_feature_disabled_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "zstd compression is disabled; rebuild with the zstd-compression feature",
    )
}

fn decompress_lz4(data: &[u8], max_size: usize) -> io::Result<Vec<u8>> {
    let Some(size_bytes) = data.get(..4) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lz4 payload is too short",
        ));
    };
    let expected_size =
        u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]) as usize;
    if expected_size > max_size {
        return Err(decompressed_size_error(expected_size, max_size));
    }
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn decompress_gzip(data: &[u8], max_size: usize) -> io::Result<Vec<u8>> {
    read_limited(GzDecoder::new(data), max_size)
}

fn read_limited<R>(reader: R, max_size: usize) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut limited = reader.take((max_size as u64) + 1);
    let mut decompressed = Vec::new();
    limited.read_to_end(&mut decompressed)?;
    ensure_decompressed_size(decompressed.len())?;
    Ok(decompressed)
}

fn ensure_decompressed_size(size: usize) -> io::Result<()> {
    if size > MAX_MESSAGE_SIZE {
        Err(decompressed_size_error(size, MAX_MESSAGE_SIZE))
    } else {
        Ok(())
    }
}

fn decompressed_size_error(size: usize, max_size: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("decompressed message too large: {size} bytes > {max_size} bytes"),
    )
}
