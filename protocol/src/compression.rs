use flate2::Compression as GzipLevel;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::str::FromStr;

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
    match mode {
        CompressionMode::None => Ok(data.to_vec()),
        CompressionMode::Zstd => decompress_zstd(data),
        CompressionMode::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        CompressionMode::Gzip => {
            let mut decoder = GzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
    }
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
fn decompress_zstd(data: &[u8]) -> io::Result<Vec<u8>> {
    zstd::decode_all(data)
}

#[cfg(not(feature = "zstd-compression"))]
fn decompress_zstd(_data: &[u8]) -> io::Result<Vec<u8>> {
    Err(zstd_feature_disabled_error())
}

#[cfg(not(feature = "zstd-compression"))]
fn zstd_feature_disabled_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "zstd compression is disabled; rebuild with the zstd-compression feature",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_roundtrip() {
        let data = b"Hello, World! This is a test of compression. ".repeat(100);

        #[cfg(feature = "zstd-compression")]
        let modes = [
            CompressionMode::None,
            CompressionMode::Zstd,
            CompressionMode::Lz4,
            CompressionMode::Gzip,
        ];
        #[cfg(not(feature = "zstd-compression"))]
        let modes = [
            CompressionMode::None,
            CompressionMode::Lz4,
            CompressionMode::Gzip,
        ];

        for mode in modes {
            let compressed = compress(&data, mode).unwrap();
            let decompressed = decompress(&compressed, mode).unwrap();
            assert_eq!(
                data.as_slice(),
                decompressed.as_slice(),
                "Failed for mode: {:?}",
                mode
            );
        }
    }

    #[test]
    fn test_compression_flag_roundtrip() {
        for mode in [
            CompressionMode::None,
            CompressionMode::Zstd,
            CompressionMode::Lz4,
            CompressionMode::Gzip,
        ] {
            let flag = mode.to_flag();
            let restored = CompressionMode::from_flag(flag);
            assert_eq!(mode, restored);
        }
    }

    #[test]
    fn test_compression_from_str() {
        assert_eq!(
            "zstd".parse::<CompressionMode>().unwrap(),
            CompressionMode::Zstd
        );
        assert_eq!(
            "ZSTD".parse::<CompressionMode>().unwrap(),
            CompressionMode::Zstd
        );
        assert_eq!(
            "lz4".parse::<CompressionMode>().unwrap(),
            CompressionMode::Lz4
        );
        assert_eq!(
            "gzip".parse::<CompressionMode>().unwrap(),
            CompressionMode::Gzip
        );
        assert_eq!(
            "gz".parse::<CompressionMode>().unwrap(),
            CompressionMode::Gzip
        );
        assert_eq!(
            "none".parse::<CompressionMode>().unwrap(),
            CompressionMode::None
        );
        assert_eq!(
            "invalid".parse::<CompressionMode>().unwrap(),
            CompressionMode::None
        );
    }

    #[cfg(not(feature = "zstd-compression"))]
    #[test]
    fn test_zstd_requires_feature() {
        let err = compress(b"data", CompressionMode::Zstd).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
