use super::*;

pub(crate) fn cleanup_stale_routes(route_state_file: Option<&str>) {
    let mut mgr = match RouteManager::new() {
        Ok(mgr) => mgr,
        Err(e) => {
            warn!("RouteManager 初始化失败，无法预清理遗留 TUN 路由：{e}");
            return;
        }
    };
    RouteLease::new(route_state_file).cleanup_stale_routes(&mut mgr);
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(super) enum RouteKind {
    ProxyBypass,
    /// 局域网/链路本地/组播旁路路由，避免 TUN split-default 抢走
    /// 依赖物理网络接口语义的发现与投屏流量。
    LocalNetworkBypass,
    DnsCapture,
    Ipv4SplitDefault,
    Ipv6SplitDefault,
    /// macOS 专属：通过原默认网关安装的 ifscope 默认路由，
    /// 让绑定到物理接口的直连套接字能找到合法下一跳。
    MacosScopedDefaultBypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RouteRecord {
    pub(super) kind: RouteKind,
    pub(super) destination: IpAddr,
    pub(super) prefix: u8,
    pub(super) gateway: Option<IpAddr>,
    #[serde(default)]
    pub(super) if_name: Option<String>,
    pub(super) if_index: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct RouteState {
    pub(super) version: u8,
    pub(super) pid: u32,
    pub(super) created_unix_secs: u64,
    pub(super) routes: Vec<RouteRecord>,
}

pub(super) struct RouteLease {
    pub(super) path: PathBuf,
    pub(super) state: RouteState,
    pub(super) persist_failed: bool,
}

impl RouteLease {
    pub(super) fn new(route_state_file: Option<&str>) -> Self {
        Self {
            path: route_state_file_path(route_state_file),
            state: RouteState {
                version: ROUTE_STATE_VERSION,
                pid: std::process::id(),
                created_unix_secs: now_unix_secs(),
                routes: Vec::new(),
            },
            persist_failed: false,
        }
    }

    pub(super) fn cleanup_stale_routes(&self, mgr: &mut RouteManager) {
        let state = match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<RouteState>(&content) {
                Ok(state) => state,
                Err(e) => {
                    warn!(
                        "TUN 路由状态文件 {} 解析失败，将移除该文件：{e}",
                        self.path.display()
                    );
                    remove_file_if_exists(&self.path);
                    return;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("读取 TUN 路由状态文件 {} 失败：{e}", self.path.display());
                return;
            }
        };

        if state.routes.is_empty() {
            remove_file_if_exists(&self.path);
            return;
        }

        info!(
            "发现上次 TUN 模式遗留的路由状态文件：{}，准备清理 {} 条路由",
            self.path.display(),
            state.routes.len()
        );

        let mut cleanup_ok = true;
        for record in state.routes.iter().rev() {
            if !delete_recorded_route(mgr, record) {
                cleanup_ok = false;
            }
        }

        if cleanup_ok {
            remove_file_if_exists(&self.path);
            info!("上次遗留的 TUN 路由已清理完成");
        } else {
            warn!(
                "上次遗留的部分 TUN 路由未能清理，保留状态文件以便下次重试：{}",
                self.path.display()
            );
        }
    }

    pub(super) fn record_installed(&mut self, kind: RouteKind, route: &Route) {
        self.state.routes.push(RouteRecord::from_route(kind, route));
        if let Err(e) = self.persist() {
            self.persist_failed = true;
            warn!("写入 TUN 路由状态文件 {} 失败：{e}", self.path.display());
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        let tmp_path = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        fs::write(&tmp_path, data)?;
        #[cfg(windows)]
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        fs::rename(tmp_path, &self.path)
    }

    pub(super) fn clear(&mut self) {
        if self.persist_failed {
            debug!(
                "TUN 路由状态文件此前写入失败，无需清理：{}",
                self.path.display()
            );
        }
        remove_file_if_exists(&self.path);
        self.state.routes.clear();
    }
}

impl RouteRecord {
    pub(super) fn from_route(kind: RouteKind, route: &Route) -> Self {
        let if_name = route.if_name().cloned();
        #[cfg(target_os = "macos")]
        let if_name = if_name.or_else(|| interface_name_for_index(route.if_index()));

        Self {
            kind,
            destination: route.destination(),
            prefix: route.prefix(),
            gateway: route.gateway(),
            if_name,
            if_index: route.if_index(),
        }
    }

    pub(super) fn to_route(&self) -> Route {
        let mut route = Route::new(self.destination, self.prefix);
        if let Some(gateway) = self.gateway {
            route = route.with_gateway(gateway);
        }
        #[cfg(target_os = "macos")]
        if let Some(if_name) = &self.if_name {
            route = route.with_if_name(if_name.clone());
        }
        if let Some(if_index) = self.if_index {
            route = route.with_if_index(if_index);
        }
        route
    }

    pub(super) fn matches_route(&self, route: &Route) -> bool {
        route.destination() == self.destination
            && route.prefix() == self.prefix
            && gateways_match(self.gateway, route.gateway(), self.destination)
            && interfaces_match(self, route)
    }
}

fn gateways_match(recorded: Option<IpAddr>, actual: Option<IpAddr>, destination: IpAddr) -> bool {
    match (recorded, actual) {
        (Some(recorded), Some(actual)) => recorded == actual,
        (None, None) => true,
        (None, Some(actual)) => is_unspecified_gateway(actual, destination),
        (Some(recorded), None) => is_unspecified_gateway(recorded, destination),
    }
}

pub(super) fn is_unspecified_gateway(gateway: IpAddr, destination: IpAddr) -> bool {
    gateway.is_ipv4() == destination.is_ipv4()
        && match gateway {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
}

fn interfaces_match(record: &RouteRecord, route: &Route) -> bool {
    let index_matches = record
        .if_index
        .zip(route.if_index())
        .is_some_and(|(expected, actual)| expected == actual);
    let name_matches = record
        .if_name
        .as_deref()
        .zip(route.if_name().map(String::as_str))
        .is_some_and(|(expected, actual)| expected == actual);

    match (record.if_index.is_some(), record.if_name.is_some()) {
        (false, false) => true,
        (true, false) => index_matches,
        (false, true) => name_matches,
        (true, true) => index_matches || name_matches,
    }
}

fn route_state_file_path(configured_file: Option<&str>) -> PathBuf {
    if let Some(path) = std::env::var_os("PPAASS_TUN_ROUTE_STATE") {
        return PathBuf::from(path);
    }

    let configured_file = configured_file
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or(ROUTE_STATE_FILE_NAME);
    let path = PathBuf::from(configured_file);
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

pub(super) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn remove_file_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => debug!("已删除 TUN 路由状态文件：{}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("删除 TUN 路由状态文件 {} 失败：{e}", path.display()),
    }
}
