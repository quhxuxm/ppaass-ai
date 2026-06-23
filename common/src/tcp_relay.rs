//! TCP relay 的共享默认值和配置换算。
//!
//! agent/proxy 多处使用 `copy_bidirectional_with_sizes` 或手写读写循环；如果这些
//! buffer 大小各自散落，很难做性能 profile。这里统一把配置里的 KB 值转换成
//! 字节，并保留一个保守上下限，避免误配置导致极小 buffer 抖动或单连接占用过大。

pub const DEFAULT_STREAM_RELAY_BUFFER_SIZE: usize = 256 * 1024;
pub const MIN_STREAM_RELAY_BUFFER_SIZE: usize = 4 * 1024;
pub const MAX_STREAM_RELAY_BUFFER_SIZE: usize = 1024 * 1024;

pub fn stream_relay_buffer_size_from_kb(size_kb: usize) -> usize {
    if size_kb == 0 {
        return DEFAULT_STREAM_RELAY_BUFFER_SIZE;
    }

    size_kb
        .saturating_mul(1024)
        .clamp(MIN_STREAM_RELAY_BUFFER_SIZE, MAX_STREAM_RELAY_BUFFER_SIZE)
}

pub fn default_stream_relay_buffer_size_kb() -> usize {
    DEFAULT_STREAM_RELAY_BUFFER_SIZE / 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_buffer_zero_uses_default() {
        assert_eq!(
            stream_relay_buffer_size_from_kb(0),
            DEFAULT_STREAM_RELAY_BUFFER_SIZE
        );
    }

    #[test]
    fn default_config_value_is_256kb() {
        assert_eq!(default_stream_relay_buffer_size_kb(), 256);
    }

    #[test]
    fn relay_buffer_is_clamped() {
        assert_eq!(
            stream_relay_buffer_size_from_kb(1),
            MIN_STREAM_RELAY_BUFFER_SIZE
        );
        assert_eq!(
            stream_relay_buffer_size_from_kb(usize::MAX),
            MAX_STREAM_RELAY_BUFFER_SIZE
        );
    }
}
