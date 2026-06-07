use super::*;

impl ServerConnection {
    pub(super) async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
        // 统一把协议层读错误转换为 proxy 错误，调用方只处理业务分支。
        match self.reader.next().await {
            Some(Ok(req)) => Ok(Some(req)),
            Some(Err(e)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
            None => Ok(None), // 连接已关闭
        }
    }

    /// 在不完成认证的情况下窥探认证请求并获取用户名
    #[instrument(skip(self))]
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        // 接收认证请求
        // 第一个请求始终应为 AuthRequest（认证请求）？
        let request = match self.read_request().await? {
            Some(req) => req,
            None => return Err(ProxyError::Connection("Connection closed".to_string())),
        };

        if let ProxyRequest::Auth(auth_request) = request {
            // 先取出用户名用于查配置，完整 AuthRequest 留到 authenticate 中校验。
            let username = auth_request.username.clone();
            debug!(
                "[认证请求] username={}, timestamp={}, encrypted_aes_key_len={}",
                auth_request.username,
                auth_request.timestamp,
                auth_request.encrypted_aes_key.len()
            );
            // 保存认证请求，稍后继续使用
            self.pending_auth_request = Some(auth_request);
            Ok(username)
        } else {
            Err(ProxyError::Authentication(
                "Expected auth request".to_string(),
            ))
        }
    }

    /// 发送认证错误响应
    #[instrument(skip(self))]
    pub async fn send_auth_error(&mut self, message: &str) -> Result<()> {
        let auth_response = AuthResponse {
            success: false,
            message: message.to_string(),
            session_id: None,
        };

        self.send_response(ProxyResponse::Auth(auth_response)).await
    }

    #[instrument(skip(self, proxy_config, user_config))]
    pub async fn authenticate(
        &mut self,
        proxy_config: &ProxyConfig,
        user_config: UserConfig,
    ) -> Result<()> {
        debug!("正在认证用户连接：{}", user_config.username);

        // 使用 peek_auth_username 中读取到的待处理认证请求
        let auth_request = self
            .pending_auth_request
            .take()
            .ok_or_else(|| ProxyError::Authentication("No pending auth request".to_string()))?;

        debug!(
            "[认证请求] 正在处理：username={}, timestamp={}, encrypted_aes_key_len={}, encrypted_aes_key_hex={}",
            auth_request.username,
            auth_request.timestamp,
            auth_request.encrypted_aes_key.len(),
            hex::encode(&auth_request.encrypted_aes_key)
        );

        // 校验用户名是否匹配
        if auth_request.username != user_config.username {
            self.send_auth_error("Username mismatch").await?;
            return Err(ProxyError::Authentication("Username mismatch".to_string()));
        }

        // 校验时间戳以防止重放攻击
        let current_time = common::current_timestamp();
        if (current_time - auth_request.timestamp).abs() > proxy_config.replay_attack_tolerance {
            // 5 分钟容忍窗口
            self.send_auth_error("Timestamp expired").await?;
            return Err(ProxyError::Authentication("Timestamp expired".to_string()));
        }

        if user_config.is_expired_at(current_time)? {
            warn!("用户 {} 已过期，拒绝建立 agent 连接", user_config.username);
            self.send_auth_error("User expired").await?;
            return Err(ProxyError::Authentication("User expired".to_string()));
        }

        // 使用用户公钥解密 AES 密钥
        let user_public_key = RsaKeyPair::from_public_key_pem(&user_config.public_key_pem)
            .map_err(|e| ProxyError::Authentication(format!("Invalid public key: {}", e)))?;

        let aes_key_bytes = protocol::crypto::decrypt_with_public_key(
            &user_public_key,
            &auth_request.encrypted_aes_key,
        )
        .map_err(|e| {
            error!("解密 AES 密钥失败：{}", e);
            ProxyError::Authentication(format!("Failed to decrypt AES key: {}", e))
        })?;

        debug!(
            "[认证请求] 已解密 AES key_len={}, aes_key_hex={}",
            aes_key_bytes.len(),
            hex::encode(&aes_key_bytes)
        );

        // 转换为固定长度数组
        let aes_key: [u8; 32] = aes_key_bytes
            .try_into()
            .map_err(|_| ProxyError::Authentication("Invalid AES key length".to_string()))?;

        let aes_cipher = AesGcmCipher::from_key(aes_key);

        let session_id = common::generate_id();

        // 发送认证响应
        let auth_response = AuthResponse {
            success: true,
            message: "Authentication successful".to_string(),
            session_id: Some(session_id.clone()),
        };

        debug!(
            "[认证响应] 正在发送：成功=true，会话 ID={:?}",
            auth_response.session_id
        );

        self.send_response(ProxyResponse::Auth(auth_response))
            .await?;

        self.user_config = Some(user_config);

        // 更新后续消息使用的加密状态
        self.cipher_state.set_cipher(Arc::new(aes_cipher));

        debug!("认证成功");
        Ok(())
    }

    pub(super) async fn send_response(&mut self, response: ProxyResponse) -> Result<()> {
        // 所有响应都经过 framed writer，统一走协议编码、压缩和加密。
        self.writer
            .send(response)
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send response: {}", e)))?;
        Ok(())
    }

    pub async fn handle_pre_connect_request(
        &mut self,
        pre_connect_idle_timeout: Duration,
        username: &str,
        mut idle_permit: Option<IdleConnectionPermit>,
    ) -> Result<()> {
        // 只在“认证完成但还没收到第一个 Connect”的阶段使用 idle 超时。
        // 一旦 Connect 到达，就移交给具体的 relay / Yamux session，不再用该超时杀外层连接。
        loop {
            let request =
                match tokio::time::timeout(pre_connect_idle_timeout, self.read_request()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        warn!(
                            "用户 '{}' 的预热连接等待 Connect 超时（{} 秒），正在关闭以防止泄漏",
                            username,
                            pre_connect_idle_timeout.as_secs()
                        );
                        return Ok(());
                    }
                };

            match request {
                Some(ProxyRequest::Connect(connect_request)) => {
                    // 从这里开始，这条 agent 连接不再算作“已认证但未 Connect”的 idle 连接。
                    // 如果它是 Yamux 外层 session，不应再被 pre-connect idle timeout 杀掉；
                    // 每条 Yamux 子流会在 relay 层应用 yamux_tcp_relay_idle_timeout_secs。
                    drop(idle_permit.take());
                    debug!(
                        "[连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
                        connect_request.request_id,
                        connect_request.address,
                        connect_request.transport
                    );
                    self.handle_connect(connect_request).await?;
                    // 中继结束（连接关闭）后，返回以关闭连接
                    return Ok(());
                }
                Some(ProxyRequest::Auth(auth_request)) => {
                    debug!("处理循环中收到意外认证请求：{:?}", auth_request.username);
                }
                Some(_) => {
                    error!("连接请求之前收到意外请求类型");
                }
                None => return Ok(()), // Agent 连接已关闭
            }
        }
    }
}
