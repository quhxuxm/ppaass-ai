use super::*;

#[instrument(skip_all, fields(username = %username))]
pub(crate) async fn authenticate_and_download(
    proxy_web_url: &str,
    username: &str,
    password: &str,
) -> Result<DownloadedCredential, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("请输入用户名".to_string());
    }
    if password.len() < 8 {
        return Err("请输入密码".to_string());
    }
    let client = build_proxy_web_client()?;

    info!("开始通过配置的认证服务验证 Agent 用户");
    let response = client
        .post(endpoint(&base_url, "api/v1/agent/login")?)
        .json(&LoginPayload {
            username: &username,
            password,
        })
        .send()
        .await
        .map_err(map_request_error)?;
    let response =
        decode_json_response::<AgentLoginResponse>(response, MAX_PRIVATE_KEY_RESPONSE_BYTES)
            .await?;
    let downloaded = validate_device_token(
        AgentDeviceTokenResponse {
            account: response.account,
            profile: response.profile,
            public_key_pem: response.public_key_pem,
            proxy_identity_public_key_pem: response.proxy_identity_public_key_pem,
            private_key_pem: response.private_key_pem,
            csrf_token: String::new(),
            _session_expires_at: None,
            agent_access_token: response.agent_access_token,
            agent_access_token_expires_at: response.agent_access_token_expires_at,
            refresh_after_seconds: response.refresh_after_seconds,
        },
        normalized_url,
    )?;
    info!(
        username = %downloaded.account.username,
        key_version = downloaded.account.key_version,
        "Agent 用户认证和私钥校验成功"
    );
    Ok(downloaded)
}

#[instrument(skip_all, fields(username = %username))]
pub(crate) async fn authenticate_rotate_and_download(
    proxy_web_url: &str,
    username: &str,
    password: &str,
) -> Result<DownloadedCredential, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("当前 Agent 登录账号无效".to_string());
    }
    if password.len() < 8 {
        return Err("请输入当前密码".to_string());
    }
    let client = build_proxy_web_client()?;

    info!("开始验证 Agent 用户并轮换密钥");
    let login_response = client
        .post(endpoint(&base_url, "api/v1/auth/login")?)
        .json(&LoginPayload {
            username: &username,
            password,
        })
        .send()
        .await
        .map_err(map_request_error)?;
    let login =
        decode_json_response::<AuthenticationResponse>(login_response, MAX_NORMAL_RESPONSE_BYTES)
            .await?;
    let csrf_token = Zeroizing::new(login.csrf_token);

    if !matches!(login.account.role.as_str(), "user" | "admin") {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("Proxy Web 返回了未知的账号角色".to_string());
    }
    if login.account.status != "active" {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("账号已停用".to_string());
    }
    if login.account.linked_username.as_deref() != Some(username.as_str()) {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("当前密码对应的账号与 Agent 登录账号不一致".to_string());
    }

    let me_response = match client.get(endpoint(&base_url, "api/v1/me")?).send().await {
        Ok(response) => response,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(map_request_error(error));
        }
    };
    let me = match decode_json_response::<MeResponse>(me_response, MAX_NORMAL_RESPONSE_BYTES).await
    {
        Ok(me) => me,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    let profile = match require_active_profile(&me) {
        Ok(profile) => profile,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    if profile.username != username {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("当前账号与 Agent 登录账号不一致".to_string());
    }
    if !profile.enabled {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("Proxy 用户已停用".to_string());
    }
    if !profile
        .permissions
        .iter()
        .any(|permission| permission == "key.rotate")
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("当前账号没有轮换密钥的权限".to_string());
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= current_timestamp())
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("密钥已经过期，请先申请新密钥并等待管理员批准".to_string());
    }
    let proxy_addresses = profile.proxy_addresses.clone().unwrap_or_default();
    if let Err(error) = validate_managed_proxy_addresses(&proxy_addresses, false) {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err(error);
    }

    let rotate_response = match client
        .post(endpoint(&base_url, "api/v1/me/rotate-key")?)
        .header("x-csrf-token", csrf_token.as_str())
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(map_request_error(error));
        }
    };
    let rotated = match decode_json_response::<PrivateKeyResponse>(
        rotate_response,
        MAX_PRIVATE_KEY_RESPONSE_BYTES,
    )
    .await
    {
        Ok(rotated) => rotated,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    best_effort_logout(&client, &base_url, &csrf_token).await;

    let expected_version = profile
        .key_version
        .checked_add(1)
        .ok_or_else(|| "当前密钥版本无效".to_string())?;
    if rotated.username != profile.username || rotated.key_version != expected_version {
        return Err("Proxy Web 返回的轮换密钥与当前账号版本不一致".to_string());
    }
    let private_key_pem = Zeroizing::new(rotated.private_key_pem);
    validate_key_pair(&private_key_pem, &rotated.public_key_pem)?;
    validate_proxy_identity_public_key(&rotated.proxy_identity_public_key_pem)?;

    info!(
        username = %profile.username,
        key_version = rotated.key_version,
        "Agent 用户密钥已轮换并校验成功"
    );
    Ok(DownloadedCredential {
        proxy_addresses,
        account: AgentAuthAccount {
            username: profile.username.clone(),
            display_name: validated_display_name(login.account.display_name)?,
            avatar_url: validated_avatar_url(login.account.avatar_url)?,
            role: login.account.role,
            permissions: profile.permissions.clone(),
            key_version: rotated.key_version,
            expires_at: profile.expires_at,
        },
        private_key_pem,
        proxy_identity_public_key_pem: rotated.proxy_identity_public_key_pem,
        proxy_web_url: normalized_url,
        agent_access_token: None,
    })
}
