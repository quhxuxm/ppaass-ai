use super::*;

const MAX_HANDOFF_PATH_BYTES: usize = 4096;
const MAX_HANDOFF_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_HANDOFF_LIFETIME_SECONDS: u64 = 5 * 60;
const HANDOFF_CLAIM_PATH: &str = "/api/v1/auth/agent-handoff";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentWebSessionHandoffResponse {
    handoff_path: String,
    expires_in: u64,
}

#[instrument(skip_all)]
pub(crate) async fn request_account_management_handoff(
    proxy_web_url: &str,
    agent_access_token: &str,
) -> Result<Url, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 账户服务配置无效，请联系管理员".to_string())?;
    if agent_access_token.is_empty() {
        return Err("当前 Agent 登录缺少账户交接凭据，请重新登录".to_string());
    }

    let client = build_proxy_web_client()?;
    let response = client
        .post(endpoint(&base_url, "api/v1/agent/web-session-handoffs")?)
        .bearer_auth(agent_access_token)
        .send()
        .await
        .map_err(map_request_error)?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err("当前 Agent 登录凭据已失效，请重新登录".to_string());
    }
    let handoff = decode_json_response::<AgentWebSessionHandoffResponse>(
        response,
        MAX_HANDOFF_RESPONSE_BYTES,
    )
    .await?;
    validate_handoff_lifetime(handoff.expires_in)?;
    account_management_handoff_url(&base_url, &handoff.handoff_path)
}

pub(crate) fn account_management_handoff_url(
    base_url: &Url,
    handoff_path: &str,
) -> Result<Url, String> {
    if handoff_path.is_empty()
        || handoff_path.len() > MAX_HANDOFF_PATH_BYTES
        || !handoff_path.starts_with('/')
        || handoff_path.starts_with("//")
        || handoff_path.contains('\\')
    {
        return Err("Proxy Web 返回的账户交接地址无效".to_string());
    }
    let url = base_url
        .join(handoff_path)
        .map_err(|_| "Proxy Web 返回的账户交接地址无效".to_string())?;
    if url.origin() != base_url.origin()
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != HANDOFF_CLAIM_PATH
        || url.query().is_none()
        || url.fragment().is_some()
    {
        return Err("Proxy Web 返回的账户交接地址不可信".to_string());
    }
    Ok(url)
}

fn validate_handoff_lifetime(expires_in: u64) -> Result<(), String> {
    if !(1..=MAX_HANDOFF_LIFETIME_SECONDS).contains(&expires_in) {
        return Err("Proxy Web 返回的账户交接有效期无效".to_string());
    }
    Ok(())
}
