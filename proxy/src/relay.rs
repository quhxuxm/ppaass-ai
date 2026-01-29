use crate::{config::ProxyConfig, session::SessionManager, user_manager::UserManager};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use common::{crypto, protocol::Message};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

pub async fn start_server(
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!("Relay server listening on {}", config.listen_addr);

    // Start session cleanup task
    {
        let session_manager = session_manager.clone();
        let timeout = config.session_timeout_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                session_manager.cleanup_expired(timeout);
            }
        });
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("Accepted connection from {}", addr);

        let config = config.clone();
        let user_manager = user_manager.clone();
        let session_manager = session_manager.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, user_manager, session_manager).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    // Read authentication request
    let auth_msg = read_message(&mut stream).await?;

    let (session_id, aes_key, username) = match auth_msg {
        Message::AuthRequest {
            username,
            password_hash,
            encrypted_aes_key,
        } => {
            debug!("Authentication request from user: {}", username);

            // Verify credentials
            if !user_manager.authenticate(&username, &password_hash) {
                let response = Message::AuthResponse {
                    success: false,
                    message: "Invalid credentials".to_string(),
                    session_id: None,
                };
                write_message(&mut stream, &response).await?;
                return Err(anyhow!("Authentication failed for user: {}", username));
            }

            // Check connection limit
            if !user_manager.check_connection_limit(&username) {
                let response = Message::AuthResponse {
                    success: false,
                    message: "Connection limit reached".to_string(),
                    session_id: None,
                };
                write_message(&mut stream, &response).await?;
                return Err(anyhow!("Connection limit reached for user: {}", username));
            }

            // Decrypt AES key
            let aes_key = crypto::rsa_decrypt(&config.rsa_private_key, &encrypted_aes_key)?;

            if aes_key.len() != 32 {
                let response = Message::AuthResponse {
                    success: false,
                    message: "Invalid AES key".to_string(),
                    session_id: None,
                };
                write_message(&mut stream, &response).await?;
                return Err(anyhow!("Invalid AES key length: {}", aes_key.len()));
            }

            // Create session
            let session_id = session_manager.create_session(username.clone());

            // Increment connection count
            user_manager.increment_connections(&username);

            // Send success response
            let response = Message::AuthResponse {
                success: true,
                message: "Authentication successful".to_string(),
                session_id: Some(session_id.clone()),
            };
            write_message(&mut stream, &response).await?;

            info!("User {} authenticated, session: {}", username, session_id);

            (session_id, aes_key, username)
        }
        _ => {
            return Err(anyhow!("Expected authentication request"));
        }
    };

    // Handle data relay
    let result = relay_loop(&mut stream, &session_id, &aes_key, &user_manager).await;

    // Cleanup
    session_manager.remove_session(&session_id);
    user_manager.decrement_connections(&username);

    result
}

async fn relay_loop(
    stream: &mut TcpStream,
    session_id: &str,
    aes_key: &[u8],
    _user_manager: &Arc<UserManager>,
) -> Result<()> {
    loop {
        let msg = match read_message(stream).await {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Connection closed or error: {}", e);
                break;
            }
        };

        match msg {
            Message::Data {
                encrypted_payload,
                target_addr,
                target_port,
                ..
            } => {
                // Decrypt payload
                let payload = crypto::aes_decrypt(aes_key, &encrypted_payload)?;

                // Forward to target
                let response_data = if let (Some(addr), Some(port)) = (target_addr, target_port) {
                    forward_to_target(&addr, port, &payload).await?
                } else {
                    return Err(anyhow!("Missing target address or port"));
                };

                // Encrypt response
                let encrypted_response = crypto::aes_encrypt(aes_key, &response_data)?;

                // Send response back
                let response = Message::Response {
                    session_id: session_id.to_string(),
                    encrypted_payload: encrypted_response,
                };

                write_message(stream, &response).await?;
            }
            Message::Close { reason, .. } => {
                info!("Client closed connection: {:?}", reason);
                break;
            }
            Message::Heartbeat { .. } => {
                // Respond to heartbeat
                let response = Message::Heartbeat {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                write_message(stream, &response).await?;
            }
            _ => {
                warn!("Unexpected message type");
            }
        }
    }

    Ok(())
}

async fn forward_to_target(addr: &str, port: u16, data: &[u8]) -> Result<Vec<u8>> {
    let target = format!("{}:{}", addr, port);
    debug!("Forwarding to target: {}", target);

    let mut target_stream = TcpStream::connect(&target).await?;

    // Send data
    target_stream.write_all(data).await?;

    // Read response (with timeout)
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];

    match tokio::time::timeout(
        tokio::time::Duration::from_secs(30),
        target_stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            response.extend_from_slice(&buf[..n]);
        }
        Ok(Ok(_)) => {
            // Connection closed
        }
        Ok(Err(e)) => {
            return Err(anyhow!("Error reading from target: {}", e));
        }
        Err(_) => {
            // Timeout
        }
    }

    Ok(response)
}

async fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = msg.to_bytes()?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let mut full_msg = vec![0u8; 4 + len];
    full_msg[..4].copy_from_slice(&len_buf);
    full_msg[4..].copy_from_slice(&buf);

    Message::from_bytes(Bytes::from(full_msg))
        .map_err(|e| anyhow!("Failed to parse message: {}", e))
}
