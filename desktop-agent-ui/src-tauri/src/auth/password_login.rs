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

    if login.account.role != "user" {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("管理员账号不能用于 Agent，请使用普通用户账号登录".to_string());
    }
    if login.account.status != "active" {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("账号已停用".to_string());
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

    if let Some(linked_username) = login.account.linked_username.as_deref() {
        if linked_username != profile.username {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err("账号与 Proxy 用户绑定关系不一致，请联系管理员".to_string());
        }
    }
    if !profile.enabled {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("Proxy 用户已停用".to_string());
    }
    if !profile
        .permissions
        .iter()
        .any(|permission| permission == "key.private.read")
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("当前账号没有读取私钥的权限".to_string());
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= current_timestamp())
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("密钥已经过期，请先申请新密钥并等待管理员批准".to_string());
    }

    let private_key_response = match client
        .get(endpoint(&base_url, "api/v1/me/private-key")?)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(map_request_error(error));
        }
    };
    let private_key = match decode_json_response::<PrivateKeyResponse>(
        private_key_response,
        MAX_PRIVATE_KEY_RESPONSE_BYTES,
    )
    .await
    {
        Ok(private_key) => private_key,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    best_effort_logout(&client, &base_url, &csrf_token).await;

    if private_key.username != profile.username || private_key.key_version != profile.key_version {
        return Err("Proxy Web 返回的密钥与当前账号版本不一致".to_string());
    }
    let private_key_pem = Zeroizing::new(private_key.private_key_pem);
    validate_key_pair(&private_key_pem, &private_key.public_key_pem)?;
    validate_proxy_identity_public_key(&private_key.proxy_identity_public_key_pem)?;

    info!(
        username = %profile.username,
        key_version = profile.key_version,
        "Agent 用户认证和私钥校验成功"
    );
    Ok(DownloadedCredential {
        account: AgentAuthAccount {
            username: profile.username.clone(),
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        private_key_pem,
        proxy_identity_public_key_pem: private_key.proxy_identity_public_key_pem,
        proxy_web_url: normalized_url,
    })
}
