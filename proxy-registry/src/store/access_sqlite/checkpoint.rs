use super::*;

impl SqliteAccessLogRepository {
    /// Truncates the WAL after an explicit retention purge and reports a busy checkpoint.
    pub async fn checkpoint_wal(&self) -> Result<()> {
        let checkpoint: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&self.pool)
            .await?;
        validate_checkpoint(checkpoint, "访问记录数据库")
    }

    #[cfg(unix)]
    pub(super) fn apply_file_permissions(&self) -> Result<()> {
        let mode = self.file_permissions.unix_mode();
        for path in database_files(&self.path) {
            secure_open_and_set_mode(&path, mode, false)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn apply_file_permissions(&self) -> Result<()> {
        Ok(())
    }
}
