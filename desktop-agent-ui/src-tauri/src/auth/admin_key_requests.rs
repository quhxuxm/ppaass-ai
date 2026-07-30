use std::collections::HashSet;

use reqwest::StatusCode;
use serde::de::IgnoredAny;

use super::profile_identity::validated_avatar_url;
use super::*;
use crate::models::{AgentAdminKeyRequest, AgentAdminKeyRequestInbox, AgentAdminProxyAddress};

const MAX_ADMIN_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ADMIN_KEY_REQUESTS: usize = 2_000;
const MAX_ADMIN_PROXY_ADDRESSES: usize = 512;

#[derive(Debug)]
pub(crate) struct AgentAdminHttpError {
    pub(crate) message: String,
    pub(crate) status: Option<StatusCode>,
}

impl AgentAdminHttpError {
    pub(crate) fn is_conflict(&self) -> bool {
        self.status == Some(StatusCode::CONFLICT)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminKeyRequestsResponse {
    requests: Vec<AdminKeyRequestResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminKeyRequestResponse {
    request_id: String,
    account: AdminAccountResponse,
    proxy_address_ids: Vec<String>,
    request_message: Option<String>,
    kind: String,
    status: String,
    expected_key_version: Option<i64>,
    reviewer_account_id: Option<String>,
    reviewer_login_name: Option<String>,
    rejection_reason: Option<String>,
    requested_at: i64,
    reviewed_at: Option<i64>,
    approved_expires_at: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminAccountResponse {
    account_id: String,
    login_name: String,
    role: String,
    status: String,
    linked_username: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    auth_version: i64,
    last_login_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyAddressesResponse {
    proxy_addresses: Vec<ProxyAddressResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyAddressResponse {
    proxy_address_id: String,
    label: String,
    address: String,
    enabled: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminKeyRequestDecisionResponse {
    request: AdminKeyRequestResponse,
    user: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminErrorEnvelope {
    error: AdminErrorDetail,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminErrorDetail {
    #[serde(rename = "code")]
    _code: String,
    message: String,
}

#[derive(Serialize)]
struct ApproveKeyRequestPayload<'a> {
    expires_at: i64,
    proxy_address_ids: &'a [String],
}

#[derive(Serialize)]
struct RejectKeyRequestPayload<'a> {
    reason: Option<&'a str>,
}

pub(crate) async fn fetch_agent_admin_key_request_inbox(
    proxy_web_url: &str,
    access_token: &str,
) -> Result<AgentAdminKeyRequestInbox, AgentAdminHttpError> {
    let base_url = admin_base_url(proxy_web_url)?;
    let client = build_proxy_web_client().map_err(request_setup_error)?;
    let requests_url =
        endpoint(&base_url, "api/v1/admin/key-requests").map_err(request_setup_error)?;
    let addresses_url =
        endpoint(&base_url, "api/v1/admin/proxy-addresses").map_err(request_setup_error)?;
    let (requests, addresses) = tokio::join!(
        client.get(requests_url).bearer_auth(access_token).send(),
        client.get(addresses_url).bearer_auth(access_token).send(),
    );
    let requests = requests.map_err(|error| request_error(map_request_error(error)))?;
    let addresses = addresses.map_err(|error| request_error(map_request_error(error)))?;
    let requests = decode_admin_response::<AdminKeyRequestsResponse>(requests).await?;
    let addresses = decode_admin_response::<ProxyAddressesResponse>(addresses).await?;
    validate_admin_inbox(requests, addresses)
}

pub(crate) async fn approve_agent_admin_key_request(
    proxy_web_url: &str,
    access_token: &str,
    request_id: &str,
    expires_at: i64,
    proxy_address_ids: &[String],
) -> Result<(), AgentAdminHttpError> {
    let base_url = admin_base_url(proxy_web_url)?;
    let client = build_proxy_web_client().map_err(request_setup_error)?;
    let path = format!(
        "api/v1/admin/key-requests/{}/approve",
        encode_path_component(request_id)
    );
    let response = client
        .post(endpoint(&base_url, &path).map_err(request_setup_error)?)
        .bearer_auth(access_token)
        .json(&ApproveKeyRequestPayload {
            expires_at,
            proxy_address_ids,
        })
        .send()
        .await
        .map_err(|error| request_error(map_request_error(error)))?;
    let decision = decode_admin_response::<AdminKeyRequestDecisionResponse>(response).await?;
    validate_decision(&decision, request_id, "approved")
}

pub(crate) async fn reject_agent_admin_key_request(
    proxy_web_url: &str,
    access_token: &str,
    request_id: &str,
    reason: Option<&str>,
) -> Result<(), AgentAdminHttpError> {
    let base_url = admin_base_url(proxy_web_url)?;
    let client = build_proxy_web_client().map_err(request_setup_error)?;
    let path = format!(
        "api/v1/admin/key-requests/{}/reject",
        encode_path_component(request_id)
    );
    let response = client
        .post(endpoint(&base_url, &path).map_err(request_setup_error)?)
        .bearer_auth(access_token)
        .json(&RejectKeyRequestPayload { reason })
        .send()
        .await
        .map_err(|error| request_error(map_request_error(error)))?;
    let decision = decode_admin_response::<AdminKeyRequestDecisionResponse>(response).await?;
    validate_decision(&decision, request_id, "rejected")
}

fn admin_base_url(proxy_web_url: &str) -> Result<Url, AgentAdminHttpError> {
    normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| request_setup_error("Agent 管理服务配置无效".to_string()))
}

async fn decode_admin_response<T>(response: Response) -> Result<T, AgentAdminHttpError>
where
    T: DeserializeOwned,
{
    let (status, bytes) = read_bounded_response(response, MAX_ADMIN_RESPONSE_BYTES)
        .await
        .map_err(request_error)?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<AdminErrorEnvelope>(&bytes)
            .ok()
            .map(|envelope| envelope.error);
        return Err(api_error(status, detail));
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentAdminHttpError {
        message: "Proxy Web 返回的管理员数据格式无效".to_string(),
        status: Some(status),
    })
}

fn validate_admin_inbox(
    requests: AdminKeyRequestsResponse,
    addresses: ProxyAddressesResponse,
) -> Result<AgentAdminKeyRequestInbox, AgentAdminHttpError> {
    if requests.requests.len() > MAX_ADMIN_KEY_REQUESTS
        || addresses.proxy_addresses.len() > MAX_ADMIN_PROXY_ADDRESSES
    {
        return Err(invalid_response("管理员待办数据数量超出限制"));
    }
    let mut request_ids = HashSet::new();
    let mut output_requests = Vec::with_capacity(requests.requests.len());
    for request in requests.requests {
        validate_request(&request, &mut request_ids)?;
        output_requests.push(AgentAdminKeyRequest {
            request_id: request.request_id,
            username: request.account.login_name,
            display_name: request.account.display_name,
            avatar_url: validated_avatar_url(request.account.avatar_url)
                .map_err(|_| invalid_response("密钥申请包含无效头像"))?,
            email: request.account.email,
            request_message: request.request_message,
            kind: request.kind,
            requested_at: request.requested_at,
            proxy_address_ids: request.proxy_address_ids,
        });
    }
    let mut address_ids = HashSet::new();
    let mut output_addresses = Vec::with_capacity(addresses.proxy_addresses.len());
    for address in addresses.proxy_addresses {
        if !valid_identifier(&address.proxy_address_id)
            || !address_ids.insert(address.proxy_address_id.clone())
            || address.address.trim().is_empty()
            || address.address.len() > 512
            || address.label.len() > 256
            || address.created_at <= 0
            || address.updated_at <= 0
        {
            return Err(invalid_response("Proxy 地址目录包含无效数据"));
        }
        output_addresses.push(AgentAdminProxyAddress {
            proxy_address_id: address.proxy_address_id,
            label: address.label,
            address: address.address,
            enabled: address.enabled,
        });
    }
    Ok(AgentAdminKeyRequestInbox {
        requests: output_requests,
        proxy_addresses: output_addresses,
    })
}

fn validate_request(
    request: &AdminKeyRequestResponse,
    request_ids: &mut HashSet<String>,
) -> Result<(), AgentAdminHttpError> {
    let proxy_ids = request.proxy_address_ids.iter().collect::<HashSet<_>>();
    let metadata_valid = request.account.account_id.len() <= 256
        && matches!(request.account.role.as_str(), "user" | "admin")
        && matches!(request.account.status.as_str(), "active" | "disabled")
        && request.account.auth_version >= 0
        && request.account.created_at > 0
        && request.account.updated_at > 0
        && request
            .account
            .linked_username
            .as_deref()
            .is_none_or(|value| value.len() <= 256)
        && request.account.last_login_at.is_none_or(|value| value > 0)
        && request.expected_key_version.is_none_or(|value| value >= 0)
        && request.reviewer_account_id.is_none()
        && request.reviewer_login_name.is_none()
        && request.rejection_reason.is_none()
        && request.reviewed_at.is_none()
        && request.approved_expires_at.is_none();
    if !valid_identifier(&request.request_id)
        || !request_ids.insert(request.request_id.clone())
        || request.account.login_name.trim().is_empty()
        || request.account.login_name.len() > 256
        || !matches!(request.kind.as_str(), "initial" | "rotate")
        || request.status != "pending"
        || request.requested_at <= 0
        || request
            .request_message
            .as_deref()
            .is_some_and(|value| value.len() > 2_000)
        || request
            .account
            .display_name
            .as_deref()
            .is_some_and(|value| value.len() > 512)
        || request
            .account
            .email
            .as_deref()
            .is_some_and(|value| value.len() > 512)
        || request.proxy_address_ids.len() > 128
        || proxy_ids.len() != request.proxy_address_ids.len()
        || !request
            .proxy_address_ids
            .iter()
            .all(|id| valid_identifier(id))
        || !metadata_valid
    {
        return Err(invalid_response("密钥申请列表包含无效数据"));
    }
    Ok(())
}

fn validate_decision(
    decision: &AdminKeyRequestDecisionResponse,
    expected_id: &str,
    expected_status: &str,
) -> Result<(), AgentAdminHttpError> {
    let request = &decision.request;
    let _ = &decision.user;
    if request.request_id != expected_id || request.status != expected_status {
        return Err(invalid_response("密钥申请审批结果不一致"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn encode_path_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn api_error(status: StatusCode, detail: Option<AdminErrorDetail>) -> AgentAdminHttpError {
    let message = match status {
        StatusCode::UNAUTHORIZED => "管理员 Agent 登录凭据已失效".to_string(),
        StatusCode::FORBIDDEN => "当前账号没有管理员审批权限".to_string(),
        StatusCode::CONFLICT => "该申请已由其他管理员处理".to_string(),
        _ => detail
            .filter(|detail| !detail.message.trim().is_empty() && detail.message.len() <= 1_000)
            .map(|detail| detail.message)
            .unwrap_or_else(|| format!("Proxy Web 返回 HTTP {}", status.as_u16())),
    };
    AgentAdminHttpError {
        message,
        status: Some(status),
    }
}

fn invalid_response(message: &str) -> AgentAdminHttpError {
    AgentAdminHttpError {
        message: message.to_string(),
        status: None,
    }
}

fn request_setup_error(message: String) -> AgentAdminHttpError {
    AgentAdminHttpError {
        message,
        status: None,
    }
}

fn request_error(message: String) -> AgentAdminHttpError {
    request_setup_error(message)
}
