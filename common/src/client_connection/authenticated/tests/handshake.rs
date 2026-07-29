use super::*;

#[tokio::test]
async fn framed_stream_switches_from_clear_auth_to_encrypted_connect() {
    let mut statuses = subscribe_verified_proxy_auth_statuses();
    let user_identity = RsaKeyPair::generate(2048).unwrap();
    let user_public_key =
        RsaKeyPair::from_public_key_pem(&user_identity.public_key_to_pem().unwrap()).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let config = TestClientConfig {
        username: "alice".to_string(),
        private_key_pem: user_identity.private_key_to_pem().unwrap(),
        proxy_identity_public_key_pem: proxy_identity.public_key_to_pem().unwrap(),
    };
    let expected_address = Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    };
    let server_expected_address = expected_address.clone();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_flow = async move {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(server_io, ProxyCodec::new(cipher_state.clone()));
        let (mut writer, mut reader) = framed.split();

        let auth = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Auth(auth) => auth,
            other => panic!("expected Auth request, got {other:?}"),
        };
        auth.validate_shape().unwrap();
        let transcript = tcp_auth_request_transcript(
            auth.version,
            &auth.username,
            auth.timestamp,
            &auth.client_nonce,
        )
        .unwrap();
        verify_pss_sha256(&user_public_key, &transcript, &auth.signature).unwrap();
        let transcript_hash = tcp_auth_transcript_hash(&transcript);
        let master_secret = [11_u8; TCP_MASTER_SECRET_LEN];
        let server_nonce = [22_u8; TCP_SERVER_NONCE_LEN];
        let session_id = [33_u8; TCP_SESSION_ID_LEN];
        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: transcript_hash,
            client_nonce: auth.client_nonce,
            server_nonce,
            session_id,
            master_secret,
        };
        let encrypted_session = encrypt_oaep_sha256_labelled(
            &user_public_key,
            TCP_OAEP_LABEL,
            &encode_tcp_session_secret(&secret).unwrap(),
        )
        .unwrap();
        let response_transcript = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &transcript_hash,
            &encrypted_session,
        )
        .unwrap();
        let response_signature = proxy_identity
            .sign_pss_sha256(&response_transcript)
            .unwrap();
        let server_cipher = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            master_secret,
            transcript_hash,
            auth.client_nonce,
            server_nonce,
            session_id,
        )
        .unwrap();

        // The successful AuthResponse is the final clear envelope. Only
        // after it has been written may either codec accept business data.
        writer
            .send(ProxyResponse::Auth(AuthResponse::success(
                encrypted_session,
                response_signature,
            )))
            .await
            .unwrap();
        cipher_state
            .set_session_cipher(Arc::new(server_cipher))
            .unwrap();

        let connect = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Connect(connect) => connect,
            other => panic!("expected encrypted Connect request, got {other:?}"),
        };
        assert_eq!(connect.address, server_expected_address);
        assert_eq!(connect.transport, TransportProtocol::Tcp);
        let request_id = connect.request_id.clone();
        writer
            .send(ProxyResponse::Connect(ConnectResponse {
                request_id: connect.request_id,
                success: true,
                message: "connected".to_string(),
            }))
            .await
            .unwrap();
        request_id
    };

    let client_flow = async {
        let connection = AuthenticatedConnection::authenticate_stream(client_io, &config)
            .await
            .unwrap();
        let (_stream, request_id) = connection
            .connect_to_target(expected_address, TransportProtocol::Tcp)
            .await
            .unwrap();
        request_id
    };

    let (server_request_id, client_request_id) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server_flow, client_flow)
        })
        .await
        .unwrap();
    assert_eq!(server_request_id, client_request_id);
    loop {
        let status = statuses.recv().await.unwrap();
        if status.username() == "alice" {
            assert_eq!(
                status,
                VerifiedProxyAuthStatus::Active {
                    username: "alice".to_string(),
                }
            );
            break;
        }
    }
}
