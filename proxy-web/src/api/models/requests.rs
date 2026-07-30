use super::super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordLoginRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChangePasswordRequest {
    pub(crate) current_password: String,
    pub(crate) new_password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateMyProfileRequest {
    #[serde(default)]
    pub(crate) display_name: PatchField<String>,
    #[serde(default)]
    pub(crate) avatar_data_url: PatchField<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitKeyRequest {
    #[serde(default)]
    pub(crate) message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentDeviceAuthorizationStartRequest {
    pub(crate) platform: String,
    #[serde(default)]
    pub(crate) client_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentUserCodeRequest {
    pub(crate) user_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentDeviceTokenRequest {
    pub(crate) device_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentWebSessionHandoffQuery {
    pub(crate) code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminCreateUserRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    pub(crate) expires_at: ExpiresAtValue,
    #[serde(default)]
    pub(crate) permissions: Option<Vec<String>>,
    pub(crate) proxy_address_ids: Vec<String>,
    #[serde(default = "enabled_by_default")]
    pub(crate) enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminUpdateUserRequest {
    #[serde(default)]
    pub(crate) role: Option<AccountRole>,
    #[serde(default)]
    pub(crate) status: Option<AccountStatus>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    #[serde(default)]
    pub(crate) permissions: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) proxy_address_ids: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) expires_at: PatchField<ExpiresAtValue>,
    #[serde(default)]
    pub(crate) display_name: PatchField<String>,
    #[serde(default)]
    pub(crate) email: PatchField<String>,
    #[serde(default)]
    pub(crate) avatar_url: PatchField<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApproveKeyRequest {
    pub(crate) expires_at: ExpiresAtValue,
    pub(crate) proxy_address_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RejectKeyRequest {
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateProxyAddressRequest {
    #[serde(default)]
    pub(crate) label: Option<String>,
    pub(crate) address: String,
    #[serde(default = "enabled_by_default")]
    pub(crate) enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateProxyAddressRequest {
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) address: Option<String>,
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessRecordsQuery {
    #[serde(default)]
    pub(crate) since: Option<i64>,
    #[serde(default = "default_access_record_limit")]
    pub(crate) limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateAccessLogSettingsRequest {
    pub(crate) retention_days: u16,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum ExpiresAtValue {
    String(String),
    Timestamp(i64),
}

#[derive(Debug, Default)]
pub(crate) enum PatchField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}
