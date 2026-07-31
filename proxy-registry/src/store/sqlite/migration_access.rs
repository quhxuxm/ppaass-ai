use super::*;

pub(super) async fn migrate_access_records_to_v4(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE user_access_records_v4 (
            record_id INTEGER NOT NULL PRIMARY KEY,
            username TEXT COLLATE BINARY NOT NULL,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
            target_host TEXT COLLATE NOCASE NOT NULL
                CHECK(length(target_host) > 0 AND length(target_host) <= 1024),
            target_port INTEGER NOT NULL CHECK(target_port BETWEEN 1 AND 65535),
            access_count INTEGER NOT NULL CHECK(access_count >= 1),
            accessed_at INTEGER NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
                ON UPDATE CASCADE ON DELETE CASCADE,
            UNIQUE(username, target_host)
        )
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        WITH normalized AS (
            SELECT
                record_id,
                username,
                protocol,
                lower(target_host) AS target_host,
                target_port,
                accessed_at
            FROM user_access_records
        ),
        ranked AS (
            SELECT
                record_id,
                username,
                protocol,
                target_host,
                target_port,
                COUNT(*) OVER (
                    PARTITION BY username, target_host
                ) AS access_count,
                accessed_at,
                ROW_NUMBER() OVER (
                    PARTITION BY username, target_host
                    ORDER BY accessed_at DESC, record_id DESC
                ) AS recency_rank
            FROM normalized
        )
        INSERT INTO user_access_records_v4 (
            record_id,
            username,
            protocol,
            target_host,
            target_port,
            access_count,
            accessed_at
        )
        SELECT
            record_id,
            username,
            protocol,
            target_host,
            target_port,
            access_count,
            accessed_at
        FROM ranked
        WHERE recency_rank = 1
        "#,
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DROP TABLE user_access_records")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("ALTER TABLE user_access_records_v4 RENAME TO user_access_records")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "CREATE INDEX idx_access_records_user_time \
         ON user_access_records(username, accessed_at DESC, record_id DESC)",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("CREATE INDEX idx_access_records_time ON user_access_records(accessed_at)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
