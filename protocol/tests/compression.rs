use protocol::message::MAX_MESSAGE_SIZE;
use protocol::{CompressionMode, compress, decompress};
use std::io;

#[test]
fn compression_roundtrip() {
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
            "Failed for mode: {mode:?}"
        );
    }
}

#[test]
fn compression_flag_roundtrip() {
    for mode in [
        CompressionMode::None,
        CompressionMode::Zstd,
        CompressionMode::Lz4,
        CompressionMode::Gzip,
    ] {
        assert_eq!(mode, CompressionMode::from_flag(mode.to_flag()));
    }
}

#[test]
fn compression_from_str() {
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

#[test]
fn lz4_decompression_rejects_declared_size_over_limit() {
    let mut payload = ((MAX_MESSAGE_SIZE + 1) as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(&[0; 8]);

    let err = decompress(&payload, CompressionMode::Lz4).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn gzip_decompression_is_limited() {
    let oversized = vec![b'a'; MAX_MESSAGE_SIZE + 1];
    let compressed = compress(&oversized, CompressionMode::Gzip).unwrap();

    let err = decompress(&compressed, CompressionMode::Gzip).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[cfg(not(feature = "zstd-compression"))]
#[test]
fn zstd_requires_feature() {
    let err = compress(b"data", CompressionMode::Zstd).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
}
