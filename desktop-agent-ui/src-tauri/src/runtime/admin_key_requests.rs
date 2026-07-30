use std::collections::HashSet;

use super::*;

impl AgentRuntime {
    pub(crate) fn admin_key_request_inbox(&self) -> Result<AgentAdminKeyRequestInbox, String> {
        self.admin_key_request_inbox
            .lock()
            .map_err(|_| "管理员密钥申请状态锁已损坏".to_string())
            .map(|inbox| inbox.clone())
    }

    pub(crate) fn replace_admin_key_request_inbox(
        &self,
        next: AgentAdminKeyRequestInbox,
    ) -> Result<(AgentAdminKeyRequestUpdate, Vec<String>), String> {
        let mut current = self
            .admin_key_request_inbox
            .lock()
            .map_err(|_| "管理员密钥申请状态锁已损坏".to_string())?;
        let previous_ids = current
            .requests
            .iter()
            .map(|request| request.request_id.as_str())
            .collect::<HashSet<_>>();
        let new_ids = next
            .requests
            .iter()
            .filter(|request| !previous_ids.contains(request.request_id.as_str()))
            .map(|request| request.request_id.clone())
            .collect();
        *current = next.clone();
        Ok((
            AgentAdminKeyRequestUpdate {
                inbox: next,
                error: None,
            },
            new_ids,
        ))
    }

    pub(crate) fn remove_admin_key_request(
        &self,
        request_id: &str,
    ) -> Result<AgentAdminKeyRequestUpdate, String> {
        let mut current = self
            .admin_key_request_inbox
            .lock()
            .map_err(|_| "管理员密钥申请状态锁已损坏".to_string())?;
        current
            .requests
            .retain(|request| request.request_id != request_id);
        Ok(AgentAdminKeyRequestUpdate {
            inbox: current.clone(),
            error: None,
        })
    }

    pub(crate) fn clear_admin_key_request_inbox(&self) -> Result<(), String> {
        *self
            .admin_key_request_inbox
            .lock()
            .map_err(|_| "管理员密钥申请状态锁已损坏".to_string())? =
            AgentAdminKeyRequestInbox::default();
        Ok(())
    }

    pub(crate) fn admin_key_request_error_update(
        &self,
        message: String,
    ) -> Result<AgentAdminKeyRequestUpdate, String> {
        Ok(AgentAdminKeyRequestUpdate {
            inbox: self.admin_key_request_inbox()?,
            error: Some(message),
        })
    }
}
