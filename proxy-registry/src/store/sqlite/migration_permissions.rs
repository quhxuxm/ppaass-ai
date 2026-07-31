use super::*;

pub(super) async fn migrate_permissions_to_v7(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<u64> {
    let rows = sqlx::query("SELECT username, permissions FROM users")
        .fetch_all(&mut **transaction)
        .await?;
    let mut updated = 0_u64;

    for row in rows {
        let username: String = row.try_get("username")?;
        let encoded: String = row.try_get("permissions")?;
        let mut permissions = decode_permissions(&encoded).map_err(|error| {
            UserRepositoryError::InvalidSchema(format!(
                "用户 {username} 的 permissions 无效：{error}"
            ))
        })?;
        let original_len = permissions.len();
        permissions.retain(|permission| permission != DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION);
        if permissions.len() == original_len {
            continue;
        }
        sqlx::query("UPDATE users SET permissions = ? WHERE username = ?")
            .bind(encode_permissions(&permissions))
            .bind(username)
            .execute(&mut **transaction)
            .await?;
        updated += 1;
    }

    Ok(updated)
}
