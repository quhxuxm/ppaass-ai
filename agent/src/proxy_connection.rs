#![allow(dead_code)]
// NOTE: This module is deprecated and replaced by multiplexer.rs for connection pooling with multiplexing

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use protocol::{
    crypto::{AesGcmCipher, RsaKeyPair},
    Address, AuthRequest, ConnectRequest, DataPacket, Message, MessageType,
    ProxyCodec, ProxyRequest, ProxyResponse,
};
use futures::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::codec::Framed;
use tracing::{debug, info};
use std::sync::Arc;

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, Message>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

pub struct ProxyConnection {
    writer: Arc<Mutex<FramedWriter>>,
    reader: Arc<Mutex<FramedReader>>,
    aes_cipher: Arc<AesGcmCipher>,
    #[allow(dead_code)]
    session_id: Option<String>,
}

impl ProxyConnection {
    pub async fn connect(config: &AgentConfig) -> Result<Self> {
        info!("Connecting to proxy: {}", config.proxy_addr);
        let stream = TcpStream::connect(&config.proxy_addr)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        let framed = Framed::new(stream, ProxyCodec::new());
        let (writer, reader) = framed.split();

        // Generate AES key for the session
        let aes_cipher = AesGcmCipher::new();
        let aes_key = aes_cipher.key().clone();

        // Load user's private key to encrypt the AES key
        let private_key_pem = std::fs::read_to_string(&config.private_key_path)
            .map_err(|e| AgentError::Authentication(format!("Failed to read private key: {}", e)))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)?;

        // Encrypt AES key with user's private key (proxy will decrypt with user's public key)
        let encrypted_aes_key = rsa_keypair.encrypt_with_private_key(&aes_key)?;

        let writer = Arc::new(Mutex::new(writer));
        let reader = Arc::new(Mutex::new(reader));

        // Authenticate
        let session_id = Self::do_authenticate(
            &writer,
            &reader,
            config.username.clone(),
            encrypted_aes_key,
        ).await?;

        Ok(Self {
            writer,
            reader,
            aes_cipher: Arc::new(aes_cipher),
            session_id,
        })
    }

    async fn do_authenticate(
        writer: &Arc<Mutex<FramedWriter>>,
        reader: &Arc<Mutex<FramedReader>>,
        username: String,
        encrypted_aes_key: Vec<u8>,
    ) -> Result<Option<String>> {
        info!("Authenticating with proxy");

        // Create auth request
        let auth_request = AuthRequest {
            username: username.clone(),
            timestamp: common::current_timestamp(),
            encrypted_aes_key: encrypted_aes_key.clone(),
        };

        debug!(
            "[AUTH REQUEST] username={}, timestamp={}, encrypted_aes_key_len={}, encrypted_aes_key_hex={}",
            username,
            auth_request.timestamp,
            encrypted_aes_key.len(),
            hex::encode(&encrypted_aes_key)
        );

        let payload = serde_json::to_vec(&ProxyRequest::Auth(auth_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let message = Message::new(MessageType::AuthRequest, payload.clone());

        debug!(
            "[AUTH REQUEST] Sending message: type={:?}, payload_len={}, payload_hex={}",
            message.message_type,
            message.payload.len(),
            hex::encode(&payload)
        );

        // Send auth request
        {
            let mut w = writer.lock().await;
            w.send(message).await.map_err(|e| AgentError::Protocol(
                protocol::ProtocolError::Io(e)
            ))?;
        }

        debug!("[AUTH REQUEST] Message sent, waiting for response...");

        // Receive auth response
        let response_message = Self::read_message(reader).await?;

        debug!(
            "[AUTH RESPONSE] Received message: type={:?}, payload_len={}, payload_hex={}",
            response_message.message_type,
            response_message.payload.len(),
            hex::encode(&response_message.payload)
        );

        let response: ProxyResponse = serde_json::from_slice(&response_message.payload)
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match response {
            ProxyResponse::Auth(ref auth_response) => {
                debug!(
                    "[AUTH RESPONSE] success={}, message={}, session_id={:?}",
                    auth_response.success,
                    auth_response.message,
                    auth_response.session_id
                );
                if auth_response.success {
                    info!("Authentication successful");
                    Ok(auth_response.session_id.clone())
                } else {
                    Err(AgentError::Authentication(auth_response.message.clone()))
                }
            }
            _ => Err(AgentError::Protocol(
                protocol::ProtocolError::InvalidMessage("Unexpected response".to_string()),
            )),
        }
    }

    async fn read_message(reader: &Arc<Mutex<FramedReader>>) -> Result<Message> {
        let mut r = reader.lock().await;
        match r.next().await {
            Some(Ok(msg)) => Ok(msg),
            Some(Err(e)) => Err(AgentError::Protocol(protocol::ProtocolError::Io(e))),
            None => Err(AgentError::Connection("Connection closed".to_string())),
        }
    }

    async fn send_message(&self, message: Message) -> Result<()> {
        let mut w = self.writer.lock().await;
        w.send(message).await.map_err(|e| AgentError::Protocol(
            protocol::ProtocolError::Io(e)
        ))?;
        Ok(())
    }

    pub async fn connect_target(&self, address: Address) -> Result<String> {
        let request_id = common::generate_id();
        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
        };

        debug!(
            "[CONNECT REQUEST] request_id={}, address={:?}",
            request_id,
            address
        );

        let payload = serde_json::to_vec(&ProxyRequest::Connect(connect_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        debug!(
            "[CONNECT REQUEST] Plain payload_hex={}",
            hex::encode(&payload)
        );

        // Encrypt payload
        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;

        let message = Message::new(MessageType::ConnectRequest, encrypted_payload.clone());

        debug!(
            "[CONNECT REQUEST] Sending message: type={:?}, encrypted_payload_len={}, encrypted_payload_hex={}",
            message.message_type,
            message.payload.len(),
            hex::encode(&encrypted_payload)
        );

        // Send connect request
        self.send_message(message).await?;

        debug!("[CONNECT REQUEST] Message sent, waiting for response...");

        // Receive connect response
        let response_message = Self::read_message(&self.reader).await?;

        debug!(
            "[CONNECT RESPONSE] Received message: type={:?}, payload_len={}, payload_hex={}",
            response_message.message_type,
            response_message.payload.len(),
            hex::encode(&response_message.payload)
        );

        // Decrypt response
        let decrypted_payload = self.aes_cipher.decrypt(&response_message.payload)?;

        debug!(
            "[CONNECT RESPONSE] Decrypted payload_hex={}",
            hex::encode(&decrypted_payload)
        );

        let response: ProxyResponse = serde_json::from_slice(&decrypted_payload)
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match response {
            ProxyResponse::Connect(ref connect_response) => {
                debug!(
                    "[CONNECT RESPONSE] request_id={}, success={}, message={}",
                    connect_response.request_id,
                    connect_response.success,
                    connect_response.message
                );
                if connect_response.success {
                    info!("Connected to target, stream_id: {}", request_id);
                    Ok(request_id)
                } else {
                    Err(AgentError::Connection(connect_response.message.clone()))
                }
            }
            _ => Err(AgentError::Protocol(
                protocol::ProtocolError::InvalidMessage("Unexpected response".to_string()),
            )),
        }
    }

    pub async fn send_data(&self, stream_id: String, data: Vec<u8>, is_end: bool) -> Result<()> {
        let data_len = data.len();
        let data_hex = hex::encode(&data);
        let data_packet = DataPacket {
            stream_id: stream_id.clone(),
            data,
            is_end,
        };

        debug!(
            "[DATA REQUEST] stream_id={}, data_len={}, is_end={}, data_hex={}",
            stream_id,
            data_len,
            is_end,
            data_hex
        );

        let payload = serde_json::to_vec(&ProxyRequest::Data(data_packet))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        debug!(
            "[DATA REQUEST] Plain payload_hex={}",
            hex::encode(&payload)
        );

        // Encrypt payload
        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;

        let message = Message::new(MessageType::Data, encrypted_payload.clone());

        debug!(
            "[DATA REQUEST] Sending message: type={:?}, encrypted_payload_len={}, encrypted_payload_hex={}",
            message.message_type,
            message.payload.len(),
            hex::encode(&encrypted_payload)
        );

        // Send data - this now only locks the writer, not blocking reader
        self.send_message(message).await?;

        debug!("[DATA REQUEST] Message sent successfully");
        Ok(())
    }

    pub async fn receive_data(&self) -> Result<DataPacket> {
        debug!("[DATA RESPONSE] Waiting for data from proxy...");

        // This now only locks the reader, not blocking writer
        let response_message = Self::read_message(&self.reader).await?;

        debug!(
            "[DATA RESPONSE] Received message: type={:?}, payload_len={}, payload_hex={}",
            response_message.message_type,
            response_message.payload.len(),
            hex::encode(&response_message.payload)
        );

        // Decrypt response
        let decrypted_payload = self.aes_cipher.decrypt(&response_message.payload)?;

        debug!(
            "[DATA RESPONSE] Decrypted payload_hex={}",
            hex::encode(&decrypted_payload)
        );

        let response: ProxyResponse = serde_json::from_slice(&decrypted_payload)
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match response {
            ProxyResponse::Data(ref data_packet) => {
                debug!(
                    "[DATA RESPONSE] stream_id={}, data_len={}, is_end={}, data_hex={}",
                    data_packet.stream_id,
                    data_packet.data.len(),
                    data_packet.is_end,
                    hex::encode(&data_packet.data)
                );
                Ok(data_packet.clone())
            }
            _ => {
                debug!("[DATA RESPONSE] Unexpected response type: {:?}", response);
                Err(AgentError::Protocol(
                    protocol::ProtocolError::InvalidMessage("Unexpected response".to_string()),
                ))
            }
        }
    }
}
