use super::super::*;

pub(crate) async fn rotate_profile_key_for_admin(
    state: &AppState,
    profile: UserRecord,
    actor: AccountActor,
    audit_reason: String,
) -> Result<UserRecord, ApiError> {
    let next_version = profile
        .key_version
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let generated =
        generate_stored_keys(&state.private_keys, &profile.username, next_version).await?;
    state
        .accounts
        .rotate_keypair(KeyPairRotation {
            username: profile.username,
            expected_key_version: profile.key_version,
            public_key_pem: generated.public_key_pem,
            encrypted_private_key: generated.encrypted_private_key,
            actor,
            audit_reason: Some(audit_reason),
        })
        .await
        .map_err(Into::into)
}

pub(crate) async fn generate_initial_stored_keys(
    state: &AppState,
    username: &str,
) -> Result<StoredKeys, ApiError> {
    generate_stored_keys(&state.private_keys, username, 1).await
}

pub(crate) async fn generate_stored_keys(
    cipher: &PrivateKeyCipher,
    username: &str,
    key_version: i64,
) -> Result<StoredKeys, ApiError> {
    let GeneratedKeys {
        public_key_pem,
        private_key_pem,
        encrypted_private_key,
    } = generate_keys(cipher, username, key_version).await?;
    // 管理端只负责生成并托管，明文私钥在入库前立即清零，不进入响应模型。
    drop(private_key_pem);
    Ok(StoredKeys {
        public_key_pem,
        encrypted_private_key,
    })
}

pub(crate) async fn generate_keys(
    cipher: &PrivateKeyCipher,
    username: &str,
    key_version: i64,
) -> Result<GeneratedKeys, ApiError> {
    let raw = tokio::task::spawn_blocking(|| {
        let pair = RsaKeyPair::generate(RSA_BITS).map_err(|_| ApiError::internal())?;
        let public_key_pem = pair.public_key_to_pem().map_err(|_| ApiError::internal())?;
        let private_key_pem = pair
            .private_key_to_pem()
            .map(Zeroizing::new)
            .map_err(|_| ApiError::internal())?;
        Ok::<_, ApiError>((public_key_pem, private_key_pem))
    })
    .await
    .map_err(|_| ApiError::internal())??;
    let encrypted_private_key = cipher
        .encrypt(username, key_version, raw.1.as_str())
        .map_err(|error| {
            warn!(username, %error, "托管私钥加密失败");
            ApiError::internal()
        })?;
    Ok(GeneratedKeys {
        public_key_pem: raw.0,
        private_key_pem: raw.1,
        encrypted_private_key,
    })
}

pub(crate) struct GeneratedKeys {
    pub(crate) public_key_pem: String,
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) encrypted_private_key: Vec<u8>,
}

pub(crate) struct StoredKeys {
    pub(crate) public_key_pem: String,
    pub(crate) encrypted_private_key: Vec<u8>,
}

impl ExpiresAtValue {
    pub(crate) fn parse(self, username: &str) -> Result<i64, ApiError> {
        let timestamp = match self {
            Self::String(value) => parse_expires_at(username, &value),
            Self::Timestamp(value) => parse_expires_at(username, &value.to_string()),
        }
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| ApiError::bad_request("expires_at 超出支持的时间范围"))?
            .format(&Rfc3339)
            .map_err(|_| ApiError::bad_request("expires_at 无法表示为 RFC3339 时间"))?;
        Ok(timestamp)
    }
}

pub(crate) fn parse_future_expiration(
    value: ExpiresAtValue,
    subject: &str,
) -> Result<i64, ApiError> {
    let expires_at = value.parse(subject)?;
    let timestamp = current_timestamp();
    if expires_at <= timestamp {
        return Err(ApiError::bad_request(
            "expires_at 必须是严格晚于当前时间的时间点",
        ));
    }
    Ok(expires_at)
}
