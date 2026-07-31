use super::super::*;

pub(crate) const MAX_NICKNAME_CHARACTERS: usize = 6;
pub(crate) const MAX_AVATAR_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_AVATAR_DIMENSION: u32 = 64;
pub(crate) const MAX_PROFILE_REQUEST_BODY_BYTES: usize = 1_500_000;

pub(crate) fn normalize_nickname(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = trim_optional(value) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_NICKNAME_CHARACTERS {
        return Err(ApiError::bad_request(format!(
            "昵称不能超过 {MAX_NICKNAME_CHARACTERS} 个字符"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::bad_request("昵称包含不允许的控制字符"));
    }
    Ok(Some(value))
}

pub(crate) fn normalize_nickname_patch(
    value: PatchField<String>,
) -> Result<Option<Option<String>>, ApiError> {
    match value {
        PatchField::Missing => Ok(None),
        PatchField::Null => Ok(Some(None)),
        PatchField::Value(value) => normalize_nickname(Some(value)).map(Some),
    }
}

pub(crate) fn normalize_avatar_patch(
    value: PatchField<String>,
) -> Result<Option<Option<String>>, ApiError> {
    match value {
        PatchField::Missing => Ok(None),
        PatchField::Null => Ok(Some(None)),
        PatchField::Value(value) => {
            normalize_avatar_data_url(&value).map(|value| Some(Some(value)))
        }
    }
}

fn normalize_avatar_data_url(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    let (prefix, encoded) = value
        .split_once(',')
        .ok_or_else(|| ApiError::bad_request("头像必须是 PNG、JPEG 或 WebP 图片"))?;
    let mime = match prefix {
        "data:image/png;base64" => "image/png",
        "data:image/jpeg;base64" => "image/jpeg",
        "data:image/webp;base64" => "image/webp",
        _ => return Err(ApiError::bad_request("头像只支持 PNG、JPEG 或 WebP 格式")),
    };
    if encoded.len() > MAX_AVATAR_BYTES.div_ceil(3) * 4 + 8 {
        return Err(ApiError::bad_request("头像文件不能超过 1 MiB"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ApiError::bad_request("头像 Base64 数据无效"))?;
    if bytes.is_empty() || bytes.len() > MAX_AVATAR_BYTES {
        return Err(ApiError::bad_request("头像文件不能超过 1 MiB"));
    }
    let (width, height) =
        image_dimensions(mime, &bytes).ok_or_else(|| ApiError::bad_request("头像图片数据无效"))?;
    if width != MAX_AVATAR_DIMENSION || height != MAX_AVATAR_DIMENSION {
        return Err(ApiError::bad_request("头像必须处理为 64 × 64 像素"));
    }
    Ok(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn image_dimensions(mime: &str, bytes: &[u8]) -> Option<(u32, u32)> {
    match mime {
        "image/png" => png_dimensions(bytes),
        "image/jpeg" => jpeg_dimensions(bytes),
        "image/webp" => webp_dimensions(bytes),
        _ => None,
    }
}

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    Some((
        u32::from_be_bytes(bytes[16..20].try_into().ok()?),
        u32::from_be_bytes(bytes[20..24].try_into().ok()?),
    ))
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || !bytes.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] != 0xff {
            offset += 1;
            continue;
        }
        while offset < bytes.len() && bytes[offset] == 0xff {
            offset += 1;
        }
        let marker = *bytes.get(offset)?;
        offset += 1;
        if matches!(marker, 0xd8 | 0xd9) {
            continue;
        }
        let length = u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?) as usize;
        if length < 2 || offset + length > bytes.len() {
            return None;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) && length >= 7
        {
            let height = u16::from_be_bytes(bytes[offset + 3..offset + 5].try_into().ok()?) as u32;
            let width = u16::from_be_bytes(bytes[offset + 5..offset + 7].try_into().ok()?) as u32;
            return Some((width, height));
        }
        offset += length;
    }
    None
}

fn webp_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 30 || !bytes.starts_with(b"RIFF") || bytes.get(8..12)? != b"WEBP" {
        return None;
    }
    match bytes.get(12..16)? {
        b"VP8X" => Some((
            1 + u32::from_le_bytes([bytes[24], bytes[25], bytes[26], 0]),
            1 + u32::from_le_bytes([bytes[27], bytes[28], bytes[29], 0]),
        )),
        b"VP8 " if bytes.get(23..26)? == [0x9d, 0x01, 0x2a] => Some((
            u16::from_le_bytes([bytes[26], bytes[27]]) as u32 & 0x3fff,
            u16::from_le_bytes([bytes[28], bytes[29]]) as u32 & 0x3fff,
        )),
        b"VP8L" if bytes.get(20) == Some(&0x2f) => {
            let bits = u32::from_le_bytes(bytes[21..25].try_into().ok()?);
            Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
        }
        _ => None,
    }
}
