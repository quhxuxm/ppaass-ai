use super::*;

pub fn account_management_page_url(value: &str) -> Result<Url, String> {
    normalize_proxy_registry_url(value)
}

pub fn normalize_proxy_registry_url(value: &str) -> Result<Url, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("请输入 Proxy Registry 地址".to_string());
    }
    let mut url = Url::parse(value).map_err(|_| "Proxy Registry 地址格式无效".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Proxy Registry 地址只支持 HTTP 或 HTTPS".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Proxy Registry 地址不能包含用户名或密码".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(
            "Proxy Registry 地址只能填写服务根地址，不能包含路径、查询参数或片段".to_string(),
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| "Proxy Registry 地址缺少主机名".to_string())?;
    if url.scheme() == "http" && !is_loopback_host(host) {
        return Err("远程 Proxy Registry 必须使用 HTTPS；HTTP 仅允许本机回环地址".to_string());
    }
    url.set_path("/");
    Ok(url)
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

pub(crate) fn endpoint(base_url: &Url, path: &str) -> Result<Url, String> {
    base_url
        .join(path)
        .map_err(|_| "构造 Proxy Registry API 地址失败".to_string())
}

pub fn validated_agent_access_token(
    value: String,
    expires_at: i64,
    refresh_after_seconds: u64,
) -> Result<AgentAccessToken, String> {
    if !(32..=4096).contains(&value.len())
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
        || expires_at <= 0
    {
        return Err("Proxy Registry 返回的 Agent 权限同步凭据无效".to_string());
    }
    Ok(AgentAccessToken {
        value: Zeroizing::new(value),
        expires_at,
        refresh_after_seconds: refresh_after_seconds.clamp(60, 3600),
    })
}

pub(crate) async fn decode_json_response<T>(
    response: Response,
    maximum_bytes: usize,
) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let (status, bytes) = read_bounded_response(response, maximum_bytes).await?;
    if !status.is_success() {
        if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&bytes) {
            return Err(map_api_error(status, envelope.error));
        }
        return Err(format!("Proxy Registry 返回 HTTP {}", status.as_u16()));
    }
    serde_json::from_slice(&bytes).map_err(|_| "Proxy Registry 响应格式无效".to_string())
}

pub(crate) async fn read_bounded_response(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<(StatusCode, Vec<u8>), String> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err("Proxy Registry 响应过大，已拒绝处理".to_string());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "读取认证服务响应失败".to_string())?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err("Proxy Registry 响应过大，已拒绝处理".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

pub fn map_api_error(status: StatusCode, error: ErrorDetail) -> String {
    match error.code.as_str() {
        "invalid_credentials" => "用户名或密码错误".to_string(),
        "key_request_required" => {
            "当前没有可用密钥，请先在用户中心提交申请并等待管理员批准".to_string()
        }
        "proxy_address_not_assigned" => "管理员尚未为当前账号分配 Proxy 地址".to_string(),
        "unauthorized" => "Proxy Registry 会话已失效，请重新登录".to_string(),
        _ => format!("认证服务返回 HTTP {}", status.as_u16()),
    }
}

pub(crate) fn map_request_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "连接认证服务超时，请稍后重试".to_string()
    } else if error.is_connect() {
        "无法连接认证服务，请联系管理员检查 Agent 配置和服务状态".to_string()
    } else {
        "认证服务请求失败，请稍后重试".to_string()
    }
}

pub(crate) async fn best_effort_logout(client: &Client, base_url: &Url, csrf_token: &str) {
    let Ok(logout_url) = endpoint(base_url, "api/v1/auth/logout") else {
        return;
    };
    match client
        .post(logout_url)
        .header("x-csrf-token", csrf_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            warn!(
                status = response.status().as_u16(),
                "清理 Proxy Registry 临时会话失败"
            );
        }
        Err(_) => warn!("清理 Proxy Registry 临时会话失败"),
    }
}

pub fn validate_key_pair(private_key_pem: &str, public_key_pem: &str) -> Result<(), String> {
    let key_pair = RsaKeyPair::from_private_key_pem(private_key_pem)
        .map_err(|_| "Proxy Registry 返回的私钥格式无效".to_string())?;
    RsaKeyPair::from_public_key_pem(public_key_pem)
        .map_err(|_| "Proxy Registry 返回的公钥格式无效".to_string())?;
    let derived_public_key = key_pair
        .public_key_to_pem()
        .map_err(|_| "无法从下载的私钥派生公钥".to_string())?;
    if normalize_pem(&derived_public_key) != normalize_pem(public_key_pem) {
        return Err("Proxy Registry 返回的公钥和私钥不匹配".to_string());
    }
    Ok(())
}

pub(crate) fn normalize_pem(value: &str) -> String {
    value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

pub fn managed_private_key_file_name(username: &str, key_version: i64) -> String {
    let username_digest = Sha256::digest(username.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("managed-{username_digest}-v{key_version}.pem")
}
