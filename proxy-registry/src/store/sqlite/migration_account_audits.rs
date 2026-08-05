use super::*;

pub(super) async fn create_v10_account_disable_audits(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE account_disable_audits (
            audit_id INTEGER NOT NULL PRIMARY KEY,
            target_account_id TEXT COLLATE BINARY NOT NULL,
            target_login_name TEXT COLLATE BINARY NOT NULL,
            admin_account_id TEXT COLLATE BINARY NOT NULL,
            admin_login_name TEXT COLLATE BINARY NOT NULL,
            disabled_at INTEGER NOT NULL,
            CHECK(length(target_account_id) BETWEEN 1 AND 128),
            CHECK(length(target_login_name) BETWEEN 1 AND 128),
            CHECK(length(admin_account_id) BETWEEN 1 AND 128),
            CHECK(length(admin_login_name) BETWEEN 1 AND 128)
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_account_disable_audits_target_time \
         ON account_disable_audits(target_account_id, disabled_at DESC, audit_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
