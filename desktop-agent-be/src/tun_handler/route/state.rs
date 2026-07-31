use super::*;

static ROUTE_STATE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn cleanup_stale_routes(route_state_file: Option<&str>) {
    if let Err(err) = cleanup_stale_routes_checked(route_state_file) {
        warn!("清理遗留 TUN 路由状态失败：{err}");
    }
}

pub(crate) fn cleanup_stale_routes_checked(route_state_file: Option<&str>) -> Result<()> {
    let mut mgr = match RouteManager::new() {
        Ok(mgr) => mgr,
        Err(e) => {
            return Err(AgentError::Connection(format!(
                "RouteManager 初始化失败，无法预清理遗留 TUN 路由：{e}"
            )));
        }
    };
    RouteLease::new(route_state_file).cleanup_stale_routes(&mut mgr)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RouteKind {
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
pub struct RouteRecord {
    pub kind: RouteKind,
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub if_name: Option<String>,
    pub if_index: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteState {
    pub version: u8,
    pub pid: u32,
    pub created_unix_secs: u64,
    pub routes: Vec<RouteRecord>,
}

pub struct RouteLease {
    pub path: PathBuf,
    pub state: RouteState,
}

impl RouteLease {
    pub fn new(route_state_file: Option<&str>) -> Self {
        Self {
            path: route_state_file_path(route_state_file),
            state: RouteState {
                version: ROUTE_STATE_VERSION,
                pid: std::process::id(),
                created_unix_secs: now_unix_secs(),
                routes: Vec::new(),
            },
        }
    }

    pub(super) fn cleanup_stale_routes(&self, mgr: &mut RouteManager) -> Result<()> {
        let state = match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<RouteState>(&content) {
                Ok(state) => state,
                Err(e) => {
                    return Err(AgentError::Connection(format!(
                        "TUN 路由状态文件 {} 解析失败，拒绝丢弃无法确认的路由恢复信息：{e}",
                        self.path.display()
                    )));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(AgentError::Connection(format!(
                    "读取 TUN 路由状态文件 {} 失败：{e}",
                    self.path.display()
                )));
            }
        };

        if state.routes.is_empty() {
            remove_file_if_exists(&self.path).map_err(|e| {
                AgentError::Connection(format!(
                    "删除空的 TUN 路由状态文件 {} 失败：{e}",
                    self.path.display()
                ))
            })?;
            return Ok(());
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
            remove_file_if_exists(&self.path).map_err(|e| {
                AgentError::Connection(format!(
                    "遗留 TUN 路由已清理，但删除状态文件 {} 失败：{e}",
                    self.path.display()
                ))
            })?;
            info!("上次遗留的 TUN 路由已清理完成");
            Ok(())
        } else {
            Err(AgentError::Connection(format!(
                "上次遗留的部分 TUN 路由未能清理，已保留状态文件以便重试：{}",
                self.path.display()
            )))
        }
    }

    pub fn record_installed(&mut self, kind: RouteKind, route: &Route) -> Result<()> {
        self.state.routes.push(RouteRecord::from_route(kind, route));
        self.persist().map_err(|e| {
            AgentError::Connection(format!(
                "持久化已安装的 TUN 路由失败，拒绝继续修改路由表：{}：{e}",
                self.path.display()
            ))
        })
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        let tmp_path = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            ROUTE_STATE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let persist_result = (|| {
            let mut file = options.open(&tmp_path)?;
            #[cfg(unix)]
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&data)?;
            file.sync_all()?;
            #[cfg(windows)]
            if self.path.exists() {
                fs::remove_file(&self.path)?;
            }
            fs::rename(&tmp_path, &self.path)?;
            sync_parent_directory(&self.path)
        })();
        if persist_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        persist_result
    }

    pub fn clear(&mut self) -> std::io::Result<()> {
        remove_file_if_exists(&self.path)?;
        self.state.routes.clear();
        Ok(())
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

    pub fn matches_route(&self, route: &Route) -> bool {
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

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            sync_parent_directory(path)?;
            debug!("已删除 TUN 路由状态文件：{}", path.display());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
