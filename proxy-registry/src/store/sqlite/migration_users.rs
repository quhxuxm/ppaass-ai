use super::*;

pub(super) async fn migrate_users_table(
    transaction: &mut Transaction<'_, Sqlite>,
    schema_version: i64,
) -> Result<()> {
    let users_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'users')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !users_exists {
        if schema_version != 0 {
            return Err(UserRepositoryError::InvalidSchema(
                "users 表不存在".to_string(),
            ));
        }
        sqlx::query(
            r#"
            CREATE TABLE users (
                username TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
                public_key_pem TEXT NOT NULL CHECK (
                    length(public_key_pem) > 0 AND length(public_key_pem) <= 16384
                ),
                permissions TEXT NOT NULL DEFAULT 'proxy.connect.tcp,proxy.connect.udp',
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                origin TEXT NOT NULL DEFAULT 'legacy'
                    CHECK(origin IN ('local', 'google', 'wechat', 'admin', 'legacy')),
                key_version INTEGER NOT NULL DEFAULT 1 CHECK(key_version >= 1),
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }

    let columns = table_columns(transaction, "users").await?;
    for required in ["username", "public_key_pem", "created_at", "updated_at"] {
        if !columns.iter().any(|column| column == required) {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "users 表缺少字段 {required}"
            )));
        }
    }
    if !columns.iter().any(|column| column == "expires_at") {
        sqlx::query("ALTER TABLE users ADD COLUMN expires_at INTEGER")
            .execute(&mut **transaction)
            .await?;
    }
    if !columns.iter().any(|column| column == "permissions") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL \
             DEFAULT 'proxy.connect.tcp,proxy.connect.udp'",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "enabled") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 \
             CHECK(enabled IN (0, 1))",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "origin") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN origin TEXT NOT NULL DEFAULT 'legacy' \
             CHECK(origin IN ('local', 'google', 'wechat', 'admin', 'legacy'))",
        )
        .execute(&mut **transaction)
        .await?;
    }
    if !columns.iter().any(|column| column == "key_version") {
        sqlx::query(
            "ALTER TABLE users ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1 \
             CHECK(key_version >= 1)",
        )
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

pub(super) async fn create_v2_tables(transaction: &mut Transaction<'_, Sqlite>) -> Result<()> {
    // v1 不应包含这些表。故意不使用 IF NOT EXISTS，以免将半成品 schema 盖章为 v2。
    sqlx::query(
        r#"
        CREATE TABLE web_accounts (
            account_id TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            login_name TEXT COLLATE BINARY NOT NULL UNIQUE,
            password_hash TEXT,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
            linked_username TEXT COLLATE BINARY UNIQUE,
            display_name TEXT,
            email TEXT,
            avatar_url TEXT,
            auth_version INTEGER NOT NULL DEFAULT 1 CHECK(auth_version >= 1),
            last_login_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(linked_username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE RESTRICT
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE external_identities (
            provider TEXT NOT NULL,
            subject TEXT NOT NULL,
            account_id TEXT COLLATE BINARY NOT NULL,
            PRIMARY KEY(provider, subject),
            FOREIGN KEY(account_id) REFERENCES web_accounts(account_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE user_private_keys (
            username TEXT COLLATE BINARY NOT NULL PRIMARY KEY,
            encrypted_private_key BLOB NOT NULL CHECK(length(encrypted_private_key) > 0),
            key_version INTEGER NOT NULL CHECK(key_version >= 1),
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "CREATE INDEX idx_web_accounts_active_admin ON web_accounts(role, status) \
         WHERE role = 'admin' AND status = 'active'",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_external_identities_account ON external_identities(account_id)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
