use super::*;
use crate::config::PERMISSION_PROXY_CONNECT_TCP;
use protocol::{DataPacket, SPEED_TEST_STREAM_ID, SpeedTestRequest};
use rand::Rng;

const SPEED_TEST_CHUNK_BYTES: usize = 64 * 1024;
const SPEED_TEST_SEND_TIMEOUT: Duration = Duration::from_secs(20);

impl ServerConnection {
    pub(super) async fn handle_speed_test(&mut self, request: SpeedTestRequest) -> Result<()> {
        if let Err(message) = request.validate_shape() {
            return self
                .send_response(ProxyResponse::Error {
                    message: message.to_string(),
                })
                .await;
        }
        if let Err(error) = self
            .validate_authorization(PERMISSION_PROXY_CONNECT_TCP)
            .await
        {
            warn!("拒绝未授权的 Proxy Entry 测速请求：{error}");
            return self
                .send_response(ProxyResponse::Error {
                    message: "Authorization no longer valid".to_string(),
                })
                .await;
        }

        let mut chunk = vec![0_u8; SPEED_TEST_CHUNK_BYTES];
        rand::rng().fill_bytes(&mut chunk);
        let send = async {
            let mut remaining = request.download_bytes as usize;
            while remaining > 0 {
                let length = remaining.min(chunk.len());
                remaining -= length;
                self.send_response(ProxyResponse::Data(DataPacket {
                    stream_id: SPEED_TEST_STREAM_ID.to_string(),
                    data: chunk[..length].to_vec(),
                    is_end: remaining == 0,
                }))
                .await?;
            }
            Ok(())
        };
        tokio::time::timeout(SPEED_TEST_SEND_TIMEOUT, send)
            .await
            .map_err(|_| ProxyError::Connection("Proxy Entry 测速发送超时".to_string()))?
    }
}
