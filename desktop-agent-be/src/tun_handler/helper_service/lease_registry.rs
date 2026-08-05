use super::*;

impl LeaseRegistry {
    pub fn trusted_state_paths(&self) -> (PathBuf, PathBuf) {
        (
            tun_helper_route_state_path(&self.state_path),
            tun_helper_dns_state_path(&self.state_path),
        )
    }

    pub fn confine_start_request(&self, mut request: TunStartRequest) -> Result<TunStartRequest> {
        let (route_state, dns_state) = self.trusted_state_paths();
        request.route_state_file = Some(confine_requested_state_path(
            "route",
            request.route_state_file.as_deref(),
            &route_state,
        )?);
        request.dns_state_file = Some(confine_requested_state_path(
            "dns",
            request.dns_state_file.as_deref(),
            &dns_state,
        )?);
        Ok(request)
    }

    pub fn persist(&self) -> Result<()> {
        if self.leases.is_empty() {
            match fs::remove_file(&self.state_path) {
                Ok(()) => {
                    sync_parent_directory(&self.state_path)?;
                    debug!(
                        "已删除空的 TUN helper lease 状态文件：{}",
                        self.state_path.display()
                    );
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "删除 TUN helper lease 状态文件失败：{}",
                            self.state_path.display()
                        )
                    });
                }
            }
            return Ok(());
        }

        let mut leases = self
            .leases
            .values()
            .map(|lease| lease.metadata.clone())
            .collect::<Vec<_>>();
        leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        persist_lease_state(
            &self.state_path,
            &PersistedLeaseState {
                version: HELPER_LEASE_STATE_VERSION,
                leases,
            },
        )
    }

    pub(super) fn stage(&mut self, mut metadata: PersistedTunLease) -> Result<()> {
        metadata.clear_runtime_proxy_addresses();
        let lease_id = metadata.lease_id.clone();
        self.leases.insert(
            lease_id.clone(),
            TunSystemLease {
                route_guard: None,
                metadata,
            },
        );
        if let Err(err) = self.persist() {
            self.leases.remove(&lease_id);
            return Err(err);
        }
        Ok(())
    }

    pub fn stage_before<T>(
        &mut self,
        metadata: PersistedTunLease,
        install: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.stage(metadata)?;
        install()
    }

    pub(super) fn attach_guard(
        &mut self,
        lease_id: &str,
        route_guard: Option<RouteGuard>,
    ) -> Result<()> {
        let Some(staged) = self.leases.get_mut(lease_id) else {
            anyhow::bail!("待激活的 TUN helper lease 不存在：{lease_id}");
        };
        staged.route_guard = route_guard;
        Ok(())
    }

    pub fn set_pf_enable_token(&mut self, lease_id: &str, token: Option<String>) -> Result<()> {
        let lease = self
            .leases
            .get_mut(lease_id)
            .with_context(|| format!("更新 PF token 时 TUN helper lease 不存在：{lease_id}"))?;
        lease.metadata.pf_enable_token = token;
        if let Err(err) = self.persist() {
            // Keep the new token in memory. The install error path immediately
            // retries cleanup through this registry; rolling back here would
            // lose the only token capable of undoing a failed `pfctl -E`.
            return Err(err.context(format!(
                "持久化 TUN helper lease={lease_id} 的 PF enable token 失败"
            )));
        }
        Ok(())
    }

    pub(super) fn release_recovered_pf_token(&mut self, lease_id: &str) -> Result<()> {
        let token = self
            .leases
            .get(lease_id)
            .with_context(|| format!("释放恢复 PF token 时 lease 不存在：{lease_id}"))?
            .metadata
            .pf_enable_token
            .clone();
        cleanup_macos_pf_dns_capture_with_token(token.as_deref())
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        self.set_pf_enable_token(lease_id, None)
    }

    pub(super) fn stop_owned(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
        owner_pid: u32,
        owner_start_time: ProcessStartTime,
    ) -> Result<bool> {
        self.stop_owned_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            owner_pid,
            owner_start_time,
            cleanup_lease_artifacts,
        )
    }

    pub fn stop_owned_with_artifact_cleanup(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
        owner_pid: u32,
        owner_start_time: ProcessStartTime,
        cleanup_artifacts: impl FnMut(Option<&str>, Option<&str>, Option<&str>) -> Result<()>,
    ) -> Result<bool> {
        let Some(lease) = self.leases.get(lease_id) else {
            // Durable lease metadata is authoritative. A duplicate/unknown
            // StopTun is idempotent and must never use untrusted hints to
            // flush the process-global PF anchor or touch another lease.
            debug!(
                "忽略未知 TUN helper lease 的 StopTun：lease={} owner_pid={}",
                lease_id, owner_pid
            );
            return Ok(false);
        };
        if lease.metadata.owner_pid != owner_pid
            || lease.metadata.owner_start_time != Some(owner_start_time)
        {
            anyhow::bail!(
                "拒绝 StopTun：lease={} 归属 owner_pid={} start_time={:?}，当前 peer_pid={} start_time={:?}",
                lease_id,
                lease.metadata.owner_pid,
                lease.metadata.owner_start_time,
                owner_pid,
                owner_start_time
            );
        }
        self.stop_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            cleanup_artifacts,
        )
    }

    pub(super) fn stop(
        &mut self,
        lease_id: &str,
        route_state_hint: Option<String>,
        dns_state_hint: Option<String>,
    ) -> Result<bool> {
        self.stop_with_artifact_cleanup(
            lease_id,
            route_state_hint,
            dns_state_hint,
            cleanup_lease_artifacts,
        )
    }

    pub fn stop_with_artifact_cleanup(
        &mut self,
        lease_id: &str,
        _route_state_hint: Option<String>,
        _dns_state_hint: Option<String>,
        mut cleanup_artifacts: impl FnMut(Option<&str>, Option<&str>, Option<&str>) -> Result<()>,
    ) -> Result<bool> {
        let Some(metadata) = self
            .leases
            .get(lease_id)
            .map(|lease| lease.metadata.clone())
        else {
            return Ok(false);
        };

        let (route_state_file, dns_state_file) = self.safe_recovery_paths(lease_id, &metadata);
        let mut retry_metadata = metadata;
        retry_metadata.cleanup_requested = true;
        retry_metadata.route_state_file = route_state_file.clone();
        retry_metadata.dns_state_file = dns_state_file.clone();

        // Persist "cleanup requested" before touching PF/routes. The original
        // owner identity remains available for an authenticated retry, while a
        // restarted helper sees this as recovery work rather than a live lease.
        self.leases
            .get_mut(lease_id)
            .expect("stop target disappeared before staging cleanup")
            .metadata = retry_metadata;
        self.persist()?;

        let cleanup_result = {
            let lease = self
                .leases
                .get_mut(lease_id)
                .expect("stop metadata was staged before cleanup");
            if let Some(route_guard) = lease.route_guard.as_mut() {
                route_guard
                    .cleanup()
                    .map_err(|err| anyhow::anyhow!(err.to_string()))
            } else {
                cleanup_artifacts(
                    route_state_file.as_deref(),
                    dns_state_file.as_deref(),
                    lease.metadata.pf_enable_token.as_deref(),
                )
            }
        };
        if let Err(cleanup_error) = cleanup_result {
            anyhow::bail!(
                "TUN helper lease={} PF/路由清理失败：{}；已保留恢复元数据，请重试停止",
                lease_id,
                cleanup_error
            );
        }

        if lease_state_files_remain_at(route_state_file.as_deref(), dns_state_file.as_deref()) {
            anyhow::bail!(
                "TUN helper lease={} 仍有状态文件未清理；已保留恢复元数据，请重试停止",
                lease_id
            );
        }

        let cleaned_lease = self
            .leases
            .remove(lease_id)
            .expect("stop metadata disappeared after cleanup");
        if let Err(persist_error) = self.persist() {
            self.leases.insert(lease_id.to_string(), cleaned_lease);
            return match self.persist() {
                Ok(()) => Err(persist_error.context(format!(
                    "TUN helper lease={lease_id} 已完成网络清理，但无法持久提交 lease 删除；已恢复重试元数据"
                ))),
                Err(restore_error) => Err(anyhow::anyhow!(
                    "TUN helper lease={lease_id} 已完成网络清理，但提交 lease 删除失败：{persist_error}；恢复重试元数据也失败：{restore_error}"
                )),
            };
        }
        Ok(true)
    }

    pub(super) fn stop_all(&mut self) -> Result<()> {
        let lease_ids = self.leases.keys().cloned().collect::<Vec<_>>();
        for lease_id in lease_ids {
            self.stop(&lease_id, None, None)?;
        }
        if !self.leases.is_empty() {
            anyhow::bail!(
                "仍有 {} 个旧 TUN helper lease 未能清理，拒绝覆盖其恢复状态",
                self.leases.len()
            );
        }
        Ok(())
    }

    pub fn cleanup_orphans_for(&mut self, operation: &str) -> Result<()> {
        let live_lease_ids = self
            .leases
            .values()
            .filter(|lease| lease_owner_is_alive(&lease.metadata))
            .map(|lease| lease.metadata.lease_id.as_str())
            .collect::<Vec<_>>();
        if !live_lease_ids.is_empty() {
            anyhow::bail!(
                "TUN helper busy：操作={}，仍被 Agent 持有的 lease={}；请先停止原 TUN",
                operation,
                live_lease_ids.join(","),
            );
        }
        self.stop_all()
    }

    pub fn route_state_owned_by_another(&self, lease_id: &str, path: &str) -> bool {
        self.leases.iter().any(|(active_id, lease)| {
            active_id != lease_id && lease.metadata.route_state_file.as_deref() == Some(path)
        })
    }

    pub fn dns_state_owned_by_another(&self, lease_id: &str, path: &str) -> bool {
        self.leases.iter().any(|(active_id, lease)| {
            active_id != lease_id && lease.metadata.dns_state_file.as_deref() == Some(path)
        })
    }

    pub(super) fn safe_recovery_paths(
        &self,
        lease_id: &str,
        metadata: &PersistedTunLease,
    ) -> (Option<String>, Option<String>) {
        let route_state_file = metadata
            .route_state_file
            .clone()
            .filter(|path| !self.route_state_owned_by_another(lease_id, path));
        let dns_state_file = metadata
            .dns_state_file
            .clone()
            .filter(|path| !self.dns_state_owned_by_another(lease_id, path));
        (route_state_file, dns_state_file)
    }
}
