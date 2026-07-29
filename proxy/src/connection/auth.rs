//! 认证阶段与 pre-connect 等待阶段。
//!
//! 一条 agent TCP 连接进入 proxy 后，第一条业务消息必须是 `Auth`。
//! proxy 先从 Auth 中取用户名查询 SQLite 用户 Repository，再用对应用户公钥验证
//! RSA-PSS 身份签名。随后由 proxy 生成会话秘密、加密给该用户，并派生方向独立的
//! 记录层密钥；认证成功后的协议帧全部受 AEAD 保护。

use super::*;
use protocol::crypto::{encrypt_oaep_sha256_labelled, verify_pss_sha256};
use protocol::tcp_transport::{
    TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_OAEP_LABEL, TCP_SERVER_NONCE_LEN,
    TCP_SESSION_ID_LEN, TcpSessionCipher, TcpSessionRole, TcpSessionSecret,
    encode_tcp_session_secret, tcp_auth_failure_signature_transcript, tcp_auth_request_transcript,
    tcp_auth_response_signature_transcript, tcp_auth_transcript_hash,
};
use rand::Rng;

const GENERIC_AUTH_FAILURE_MESSAGE: &str = "Authentication failed";

fn signed_terminal_auth_failure_response(
    transport_identity: &RsaKeyPair,
    auth_transcript_hash: &[u8; 32],
    code: AuthFailureCode,
    message: &str,
) -> Result<AuthResponse> {
    if !matches!(
        code,
        AuthFailureCode::UserDisabled | AuthFailureCode::UserExpired
    ) {
        return Err(ProxyError::Authentication(
            "Refusing to sign a non-terminal authentication failure".to_string(),
        ));
    }
    let signature_transcript = tcp_auth_failure_signature_transcript(
        TCP_HANDSHAKE_VERSION,
        auth_transcript_hash,
        code,
        message,
    )?;
    let proxy_signature = transport_identity.sign_pss_sha256(&signature_transcript)?;
    let response = AuthResponse::signed_failure(code, message, proxy_signature);
    response.validate_shape()?;
    Ok(response)
}

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
        // 接收认证请求。这里“窥探”不是偷看 TCP 缓冲区，而是正常读走第一帧，
        // 只先提取 username；完整 AuthRequest 暂存到 pending_auth_request。
        let request = match self.read_request().await? {
            Some(req) => req,
            None => return Err(ProxyError::Connection("Connection closed".to_string())),
        };

        if let ProxyRequest::Auth(auth_request) = request {
            auth_request.validate_shape().map_err(|_| {
                ProxyError::Authentication("Invalid authentication request".to_string())
            })?;
            // 先取出用户名用于查配置，完整 AuthRequest 留到 authenticate 中校验。
            let username = auth_request.username.clone();
            debug!(
                "[认证请求] version={}, username={}, timestamp={}",
                auth_request.version, auth_request.username, auth_request.timestamp
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

    /// 发送统一的未认证失败响应。
    ///
    /// 在客户端证明持有当前私钥之前，不使用 Proxy 传输身份签名，也不返回
    /// 内部原因，避免用户名存在性差异和未认证的签名 CPU oracle。
    #[instrument(skip(self))]
    pub async fn send_auth_error(&mut self) -> Result<()> {
        let auth_response = AuthResponse::failure(GENERIC_AUTH_FAILURE_MESSAGE);
        auth_response.validate_shape()?;
        self.send_response(ProxyResponse::Auth(auth_response)).await
    }

    async fn send_signed_terminal_auth_error_for_transcript(
        &mut self,
        auth_transcript_hash: &[u8; 32],
        code: AuthFailureCode,
        message: &str,
    ) -> Result<()> {
        let auth_response = signed_terminal_auth_failure_response(
            self.transport_identity.as_ref(),
            auth_transcript_hash,
            code,
            message,
        )?;
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

        auth_request.validate_shape().map_err(|_| {
            ProxyError::Authentication("Invalid authentication request".to_string())
        })?;
        debug!(
            "[认证请求] 正在处理：version={}, username={}, timestamp={}",
            auth_request.version, auth_request.username, auth_request.timestamp
        );
        let transcript = tcp_auth_request_transcript(
            auth_request.version,
            &auth_request.username,
            auth_request.timestamp,
            &auth_request.client_nonce,
        )
        .map_err(|_| ProxyError::Authentication("Invalid authentication request".to_string()))?;
        let transcript_hash = tcp_auth_transcript_hash(&transcript);

        // Repository 查询键、UserConfig.username、AuthRequest.username 必须指向
        // 同一个用户，避免拿 A 用户的配置认证 B 用户的请求。
        if auth_request.username != user_config.username {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication("Username mismatch".to_string()));
        }

        // 先校验时间戳，过期 challenge 无论账号当前状态如何都只得到通用失败，
        // 不能被拿来探测停用/过期状态。
        let current_time = common::current_timestamp();
        let replay_tolerance = proxy_config.replay_attack_tolerance.max(0) as u64;
        if current_time.abs_diff(auth_request.timestamp) > replay_tolerance {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication("Timestamp expired".to_string()));
        }

        // Agent 对域分离 transcript 做 RSA-PSS-SHA256 签名；服务端不再接受
        // 旧版“私钥加密、公钥解密”的原始 RSA 线协议。账号状态只能在这个
        // 私钥证明通过后返回，否则已知用户名会变成状态枚举接口。
        let user_public_key = match RsaKeyPair::from_public_key_pem(&user_config.public_key_pem) {
            Ok(public_key) => public_key,
            Err(error) => {
                self.send_auth_error().await?;
                return Err(ProxyError::Authentication(format!(
                    "Invalid public key: {error}"
                )));
            }
        };
        if verify_pss_sha256(&user_public_key, &transcript, &auth_request.signature).is_err() {
            warn!("用户 {} 的 TCP 认证签名无效", user_config.username);
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication(
                "Invalid authentication proof".to_string(),
            ));
        }

        // 签名验证成功后才占用有界 replay cache；状态判断也放在 claim 之后，
        // 防止捕获到的一次合法请求在窗口内被重复用于探测账号状态。
        let valid_until = auth_request
            .timestamp
            .saturating_add(proxy_config.replay_attack_tolerance.max(0));
        if !self.user_manager.claim_tcp_auth_nonce(
            &auth_request.username,
            auth_request.client_nonce,
            current_time,
            valid_until,
        ) {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication(
                "Authentication request replayed".to_string(),
            ));
        }

        // 只有已经证明持有当前私钥、且 challenge 新鲜且未重放的用户，才会
        // 收到 Agent 可采信的 signed Disabled/Expired 状态。
        if !user_config.enabled {
            warn!("用户 {} 已停用，拒绝建立 agent 连接", user_config.username);
            self.send_signed_terminal_auth_error_for_transcript(
                &transcript_hash,
                AuthFailureCode::UserDisabled,
                "User disabled",
            )
            .await?;
            return Err(ProxyError::Authentication("User disabled".to_string()));
        }

        // 用户过期属于认证边界的一部分：过期账号不再进入后续 CONNECT/relay 阶段。
        if user_config.is_expired_at(current_time)? {
            warn!("用户 {} 已过期，拒绝建立 agent 连接", user_config.username);
            self.send_signed_terminal_auth_error_for_transcript(
                &transcript_hash,
                AuthFailureCode::UserExpired,
                "User expired",
            )
            .await?;
            return Err(ProxyError::Authentication("User expired".to_string()));
        }

        // 会话主密钥只能由 Proxy 生成，并与两端 nonce、随机 session id 以及
        // 完整认证 transcript 一起派生方向独立的记录层密钥。
        let mut master_secret = [0_u8; TCP_MASTER_SECRET_LEN];
        let mut server_nonce = [0_u8; TCP_SERVER_NONCE_LEN];
        let mut session_id = [0_u8; TCP_SESSION_ID_LEN];
        {
            let mut rng = rand::rng();
            rng.fill_bytes(&mut master_secret);
            rng.fill_bytes(&mut server_nonce);
            rng.fill_bytes(&mut session_id);
        }
        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: transcript_hash,
            client_nonce: auth_request.client_nonce,
            server_nonce,
            session_id,
            master_secret,
        };
        let encoded_secret = encode_tcp_session_secret(&secret).map_err(|_| {
            ProxyError::Authentication("Failed to encode authentication response".to_string())
        })?;
        let encrypted_session =
            encrypt_oaep_sha256_labelled(&user_public_key, TCP_OAEP_LABEL, &encoded_secret)
                .map_err(|_| {
                    ProxyError::Authentication(
                        "Failed to encrypt authentication response".to_string(),
                    )
                })?;
        let proxy_signature_transcript = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &transcript_hash,
            &encrypted_session,
        )
        .map_err(|_| {
            ProxyError::Authentication(
                "Failed to build Proxy identity signature context".to_string(),
            )
        })?;
        let proxy_signature = self
            .transport_identity
            .sign_pss_sha256(&proxy_signature_transcript)
            .map_err(|_| {
                ProxyError::Authentication("Failed to sign authentication response".to_string())
            })?;
        let session_cipher = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            master_secret,
            transcript_hash,
            auth_request.client_nonce,
            server_nonce,
            session_id,
        )
        .map_err(|_| {
            ProxyError::Authentication("Failed to initialize TCP session protection".to_string())
        })?;
        let auth_response = AuthResponse::success(encrypted_session, proxy_signature);
        auth_response.validate_shape().map_err(|_| {
            ProxyError::Authentication("Invalid authentication response".to_string())
        })?;

        // 在发送成功响应前固定本次握手的身份快照。后续 CONNECT 和 active relay
        // 既检查数据库实时状态，也以该快照的 key_version/绝对 expiry 作为上界。
        let authorization = ConnectionAuthorization::new(self.user_manager.clone(), &user_config)?;
        self.send_response(ProxyResponse::Auth(auth_response))
            .await?;

        self.user_config = Some(user_config);
        self.authorization = Some(authorization);

        // 成功 AuthResponse 本身保持明文 envelope（会话材料已经 OAEP 加密）；
        // 发送完成后一次性切换到 v3 记录层，此后不接受任何明文业务帧。
        self.cipher_state
            .set_session_cipher(Arc::new(session_cipher))?;

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

    pub async fn handle_connect_request(&mut self, username: &str) -> Result<()> {
        // Yamux 子 stream 认证成功后应立即发送 Connect。这里保留一个短超时，
        // 防止异常客户端完成认证后悬挂子 stream。
        let connect_request_timeout = Duration::from_secs(self.proxy_config.auth_timeout_secs);
        loop {
            let request =
                match tokio::time::timeout(connect_request_timeout, self.read_request()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        warn!(
                            "用户 '{}' 的 Yamux 子 stream 等待 Connect 超时（{} 秒），正在关闭",
                            username,
                            connect_request_timeout.as_secs()
                        );
                        return Ok(());
                    }
                };

            match request {
                Some(ProxyRequest::Connect(connect_request)) => {
                    debug!(
                        "[连接请求] 请求 ID={}，地址={:?}，传输协议={:?}",
                        connect_request.request_id,
                        connect_request.address,
                        connect_request.transport
                    );
                    self.handle_connect(connect_request).await?;
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

#[cfg(test)]
mod tests;
