pub fn validated_display_name(value: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > 6 || value.chars().any(char::is_control) {
        return Err("Proxy Registry 返回了无效昵称".to_string());
    }
    Ok(Some(value))
}

pub fn validated_avatar_url(value: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() > 1_500_000
        || !matches!(
            value.split_once(',').map(|parts| parts.0),
            Some("data:image/png;base64")
                | Some("data:image/jpeg;base64")
                | Some("data:image/webp;base64")
        )
    {
        return Err("Proxy Registry 返回了无效头像".to_string());
    }
    Ok(Some(value))
}
