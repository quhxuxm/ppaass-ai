use super::*;

#[instrument(skip_all)]
pub(crate) async fn start_device_authorization(
    proxy_web_url: &str,
) -> Result<StartedDeviceAuthorization, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let client = build_proxy_web_client()?;
    let response = client
        .post(endpoint(&base_url, "api/v1/agent/device-authorizations")?)
        .json(&AgentDeviceAuthorizationStartPayload {
            platform: "windows",
            client_name: "PPAASS Windows Agent",
        })
        .send()
        .await
        .map_err(map_request_error)?;
    let response = decode_json_response::<AgentDeviceAuthorizationStartResponse>(
        response,
        MAX_NORMAL_RESPONSE_BYTES,
    )
    .await?;

    let device_code = Zeroizing::new(response.device_code);
    validate_device_code(&device_code)?;
    validate_user_code(&response.user_code)?;
    if !(1..=MAX_DEVICE_AUTHORIZATION_SECONDS).contains(&response.expires_in) {
        return Err("Proxy Web 返回的设备登录有效期无效".to_string());
    }
    if !(1..=MAX_DEVICE_POLL_SECONDS).contains(&response.interval) {
        return Err("Proxy Web 返回的设备登录轮询间隔无效".to_string());
    }
    let verification_url = device_verification_url(&base_url, &response.verification_uri_complete)?;
    let expires_at = current_timestamp().saturating_add(response.expires_in);
    info!(
        expires_at,
        interval_seconds = response.interval,
        "已创建 Windows Agent 浏览器设备登录"
    );
    Ok(StartedDeviceAuthorization {
        device_code,
        user_code: response.user_code,
        verification_url,
        expires_at,
        interval_seconds: response.interval,
        proxy_web_url: normalized_url,
    })
}

#[instrument(skip_all)]
pub(crate) async fn poll_device_authorization(
    proxy_web_url: &str,
    device_code: &str,
    default_interval_seconds: u32,
) -> Result<DeviceAuthorizationPoll, String> {
    validate_device_code(device_code)?;
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let client = build_proxy_web_client()?;
    let response = client
        .post(endpoint(
            &base_url,
            "api/v1/agent/device-authorizations/token",
        )?)
        .json(&AgentDeviceTokenPayload { device_code })
        .send()
        .await
        .map_err(map_request_error)?;

    if !response.status().is_success() {
        return decode_device_authorization_error(response, default_interval_seconds).await;
    }

    let mut token =
        decode_json_response::<AgentDeviceTokenResponse>(response, MAX_PRIVATE_KEY_RESPONSE_BYTES)
            .await?;
    let csrf_token = Zeroizing::new(std::mem::take(&mut token.csrf_token));
    let downloaded = validate_device_token(token, normalized_url);
    if !csrf_token.is_empty() {
        best_effort_logout(&client, &base_url, &csrf_token).await;
    }
    let downloaded = downloaded?;
    info!(
        username = %downloaded.account.username,
        key_version = downloaded.account.key_version,
        "Windows Agent 浏览器设备登录授权成功"
    );
    Ok(DeviceAuthorizationPoll::Authorized(Box::new(downloaded)))
}

pub(crate) fn open_system_browser(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("设备登录地址无效".to_string());
    }

    #[cfg(windows)]
    {
        let operation = std::ffi::OsStr::new("open")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let target = std::ffi::OsStr::new(url.as_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: both UTF-16 strings are NUL-terminated and remain alive for the call.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        if result as isize <= 32 {
            return Err("无法打开系统默认浏览器，请检查 Windows 默认浏览器设置".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url.as_str())
            .spawn()
            .map_err(|_| "无法打开系统默认浏览器".to_string())?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(url.as_str())
            .spawn()
            .map_err(|_| "无法打开系统默认浏览器".to_string())?;
        Ok(())
    }
}

pub(crate) fn validate_device_token(
    token: AgentDeviceTokenResponse,
    proxy_web_url: String,
) -> Result<DownloadedCredential, String> {
    let AgentDeviceTokenResponse {
        account,
        profile,
        public_key_pem,
        proxy_identity_public_key_pem,
        private_key_pem,
        csrf_token: _,
        _session_expires_at: _,
        agent_access_token,
        agent_access_token_expires_at,
        refresh_after_seconds,
    } = token;
    let private_key_pem = Zeroizing::new(private_key_pem);
    if !matches!(account.role.as_str(), "user" | "admin") {
        return Err("Proxy Web 返回了未知的账号角色".to_string());
    }
    if account.status != "active" {
        return Err("账号已停用".to_string());
    }
    if !profile.enabled {
        return Err("Proxy 用户已停用".to_string());
    }
    if let Some(linked_username) = account.linked_username.as_deref() {
        if linked_username != profile.username {
            return Err("账号与 Proxy 用户绑定关系不一致，请联系管理员".to_string());
        }
    }
    if !profile
        .permissions
        .iter()
        .any(|permission| permission == "key.private.read")
    {
        return Err("当前账号没有读取私钥的权限".to_string());
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= current_timestamp())
    {
        return Err("密钥已经过期，请先申请新密钥并等待管理员批准".to_string());
    }
    let proxy_addresses = profile.proxy_addresses.unwrap_or_default();
    validate_managed_proxy_addresses(&proxy_addresses, false)?;
    validate_key_pair(&private_key_pem, &public_key_pem)?;
    validate_proxy_identity_public_key(&proxy_identity_public_key_pem)?;
    let agent_access_token = validated_agent_access_token(
        agent_access_token,
        agent_access_token_expires_at,
        refresh_after_seconds,
    )?;
    Ok(DownloadedCredential {
        proxy_addresses,
        account: AgentAuthAccount {
            username: profile.username,
            display_name: validated_display_name(account.display_name)?,
            avatar_url: validated_avatar_url(account.avatar_url)?,
            role: account.role,
            permissions: profile.permissions,
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        private_key_pem,
        proxy_identity_public_key_pem,
        proxy_web_url,
        agent_access_token: Some(agent_access_token),
    })
}

pub(crate) async fn decode_device_authorization_error(
    response: Response,
    default_interval_seconds: u32,
) -> Result<DeviceAuthorizationPoll, String> {
    let status = response.status();
    let retry_after_seconds = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=MAX_DEVICE_POLL_SECONDS).contains(value))
        .unwrap_or_else(|| default_interval_seconds.clamp(1, MAX_DEVICE_POLL_SECONDS));
    let (_, bytes) = read_bounded_response(response, MAX_NORMAL_RESPONSE_BYTES).await?;
    let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes)
        .map_err(|_| format!("Proxy Web 返回 HTTP {}", status.as_u16()))?;
    match envelope.error.code.as_str() {
        "authorization_pending" => Ok(DeviceAuthorizationPoll::Pending {
            slow_down: false,
            retry_after_seconds,
        }),
        "slow_down" | "rate_limited" => Ok(DeviceAuthorizationPoll::Pending {
            slow_down: true,
            retry_after_seconds,
        }),
        "access_denied" => Err("你已在浏览器中拒绝这次设备登录".to_string()),
        "expired_token" => Err("设备登录已过期，请重新开始".to_string()),
        "invalid_device_code" => Err("设备登录码无效或已经使用，请重新开始".to_string()),
        "authorization_invalidated" => Err("账号状态已变化，请重新开始设备登录".to_string()),
        _ => Err(map_api_error(status, envelope.error)),
    }
}

pub(crate) fn validate_device_code(value: &str) -> Result<(), String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Proxy Web 返回的设备登录码格式无效".to_string());
    }
    Ok(())
}

pub(crate) fn validate_user_code(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Proxy Web 返回的设备授权短码格式无效".to_string());
    }
    Ok(())
}

pub(crate) fn device_verification_url(base_url: &Url, value: &str) -> Result<Url, String> {
    if value.is_empty() || value.len() > 2048 {
        return Err("Proxy Web 返回的设备登录地址无效".to_string());
    }
    let url = base_url
        .join(value)
        .map_err(|_| "Proxy Web 返回的设备登录地址无效".to_string())?;
    if url.origin() != base_url.origin()
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Proxy Web 返回的设备登录地址不可信".to_string());
    }
    Ok(url)
}

pub(crate) fn build_proxy_web_client() -> Result<Client, String> {
    Client::builder()
        // Proxy Web is the control plane that provisions this Agent. Routing its
        // login or private-key requests through the Agent's own data-plane proxy
        // would create a dependency loop when HTTP_PROXY points at this Agent.
        .no_proxy()
        .cookie_store(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("ppaass-desktop-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| format!("初始化 Proxy Web 客户端失败：{error}"))
}
