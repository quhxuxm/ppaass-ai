use serde::{Deserialize, Serialize};

pub const DEFAULT_SPEED_TEST_DOWNLOAD_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_SPEED_TEST_DOWNLOAD_BYTES: u32 = 4 * 1024 * 1024;
pub const MIN_SPEED_TEST_DOWNLOAD_BYTES: u32 = 64 * 1024;
pub const SPEED_TEST_STREAM_ID: &str = "ppaass-speed-test";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestRequest {
    pub download_bytes: u32,
}

impl SpeedTestRequest {
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if !(MIN_SPEED_TEST_DOWNLOAD_BYTES..=MAX_SPEED_TEST_DOWNLOAD_BYTES)
            .contains(&self.download_bytes)
        {
            return Err("speed test download size is out of range");
        }
        Ok(())
    }
}
