use super::*;

impl LeaseRegistry {
    pub(super) fn recover(socket_path: &Path) -> Result<Self> {
        let state_path = helper_lease_state_path(socket_path);
        let persisted = load_persisted_leases(&state_path)?;
        let trusted_route_state = tun_helper_route_state_path(socket_path);
        let trusted_dns_state = tun_helper_dns_state_path(socket_path);
        for metadata in &persisted {
            validate_persisted_lease_state_paths(
                metadata,
                &trusted_route_state,
                &trusted_dns_state,
            )?;
        }
        let leases = persisted
            .into_iter()
            .map(|metadata| {
                (
                    metadata.lease_id.clone(),
                    TunSystemLease {
                        route_guard: None,
                        metadata,
                    },
                )
            })
            .collect();
        let mut registry = Self { state_path, leases };
        if registry.leases.len() > 1 {
            anyhow::bail!(
                "发现 {} 个持久 TUN helper lease；PF anchor 是全局单例，拒绝在所有权不明确时恢复或清理",
                registry.leases.len()
            );
        }
        let lease_ids = registry.leases.keys().cloned().collect::<Vec<_>>();

        for lease_id in lease_ids {
            let metadata = registry
                .leases
                .get(&lease_id)
                .expect("persisted lease disappeared during recovery")
                .metadata
                .clone();
            if lease_owner_is_alive(&metadata) {
                if let Err(err) = registry.release_recovered_pf_token(&lease_id) {
                    anyhow::bail!(
                        "恢复存活 Agent 的 TUN helper lease={} 前释放旧 PF token 失败：{}；保留恢复元数据并拒绝启动",
                        lease_id,
                        err
                    );
                }
                let refreshed_metadata = registry
                    .leases
                    .get(&lease_id)
                    .expect("lease disappeared after recovered PF cleanup")
                    .metadata
                    .clone();
                let route_guard = {
                    let mut persist_pf_token = |token: Option<&str>| {
                        registry
                            .set_pf_enable_token(&lease_id, token.map(ToOwned::to_owned))
                            .map_err(|err| AgentError::Connection(err.to_string()))
                    };
                    restore_route_guard(&refreshed_metadata, &mut persist_pf_token)
                };
                match route_guard {
                    Ok(route_guard) => {
                        registry.attach_guard(&lease_id, Some(route_guard))?;
                        info!(
                            "已完整恢复 TUN helper lease={}：owner_pid={}，路由、PF DNS 捕获及 enable token 均已重建",
                            lease_id, metadata.owner_pid
                        );
                        continue;
                    }
                    Err(err) => {
                        error!(
                            "恢复存活 Agent 的 TUN helper lease={} 失败，将撤销遗留 TUN 网络状态：{}",
                            lease_id, err
                        );
                    }
                }
            } else if metadata.cleanup_requested {
                warn!(
                    "发现尚未完成清理的 TUN helper lease={}，准备继续恢复系统网络",
                    lease_id
                );
            } else {
                warn!(
                    "发现 owner_pid={} 进程实例已退出、已复用或缺少启动时间的 TUN helper lease={}，准备恢复系统网络",
                    metadata.owner_pid, lease_id
                );
            }

            if let Err(cleanup_error) = registry.stop(&lease_id, None, None) {
                anyhow::bail!(
                    "TUN helper lease={} 恢复失败且 PF/路由清理失败：{}；保留恢复元数据并拒绝启动",
                    lease_id,
                    cleanup_error
                );
            }
            info!("已清理异常退出或恢复失败的 TUN helper lease={lease_id}");
        }

        registry.persist()?;
        if !registry.leases.is_empty() {
            info!(
                "已恢复 {} 个 TUN helper lease 的完整路由/PF guard",
                registry.leases.len()
            );
        }
        Ok(registry)
    }
}
