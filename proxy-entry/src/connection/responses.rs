use super::*;

impl ServerConnection {
    pub(super) async fn send_connect_error(
        &mut self,
        request_id: String,
        message: String,
    ) -> Result<()> {
        // connect 失败也回给 agent，避免 agent 端一直等待。
        let connect_response = ConnectResponse {
            request_id,
            success: false,
            message,
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }

    pub(super) async fn send_connect_success(
        &mut self,
        request_id: String,
        message: &str,
    ) -> Result<()> {
        // connect 成功后，agent 才会开始发送该 stream 的数据。
        let connect_response = ConnectResponse {
            request_id,
            success: true,
            message: message.to_string(),
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }
}
