use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

const DNS_STATE_VERSION: u8 = 1;
const DNS_STATE_FILE_NAME: &str = "tun-dns.json";

#[derive(Debug, Serialize, Deserialize)]
struct DnsState<R> {
    version: u8,
    pid: u32,
    created_unix_secs: u64,
    records: Vec<R>,
}

pub(super) struct DnsLease<R> {
    pub(super) path: PathBuf,
    state: DnsState<R>,
    persist_failed: bool,
}

impl<R> DnsLease<R>
where
    R: Clone + Serialize + DeserializeOwned,
{
    pub(super) fn new(dns_state_file: Option<&str>) -> Self {
        Self {
            path: dns_state_file_path(dns_state_file),
            state: DnsState {
                version: DNS_STATE_VERSION,
                pid: std::process::id(),
                created_unix_secs: now_unix_secs(),
                records: Vec::new(),
            },
            persist_failed: false,
        }
    }

    pub(super) fn cleanup_stale_records(&mut self, restore_record: impl Fn(&R) -> bool) {
        let state = match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<DnsState<R>>(&content) {
                Ok(state) => state,
                Err(e) => {
                    warn!(
                        "TUN DNS 状态文件 {} 解析失败，将移除该文件：{e}",
                        self.path.display()
                    );
                    remove_file_if_exists(&self.path);
                    return;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("读取 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
                return;
            }
        };

        if state.records.is_empty() {
            remove_file_if_exists(&self.path);
            return;
        }

        if state.pid == std::process::id() || current_process_is_alive(state.pid) {
            return;
        }

        warn!(
            "检测到上次 TUN DNS 状态未清理（pid={}，created={}），尝试恢复",
            state.pid, state.created_unix_secs
        );
        self.state.records = state
            .records
            .into_iter()
            .filter(|record| !restore_record(record))
            .collect();
        self.mark_current_process();
        if self.state.records.is_empty() {
            remove_file_if_exists(&self.path);
        } else {
            self.persist();
        }
    }

    pub(super) fn record_active(&mut self, record: R) {
        self.mark_current_process();
        self.state.records.push(record);
        self.persist();
    }

    pub(super) fn remove_record(&mut self, record: &R, same_target: impl Fn(&R, &R) -> bool) {
        self.state
            .records
            .retain(|existing| !same_target(existing, record));
        if self.state.records.is_empty() {
            self.remove_state_file();
        } else {
            self.persist();
        }
    }

    fn mark_current_process(&mut self) {
        self.state.version = DNS_STATE_VERSION;
        self.state.pid = std::process::id();
        self.state.created_unix_secs = now_unix_secs();
    }

    fn persist(&mut self) {
        let create_parent_dir = match self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            Some(parent) => fs::create_dir_all(parent).map_err(|e| (parent, e)),
            None => Ok(()),
        };
        if let Err((parent, e)) = create_parent_dir {
            warn!("创建 TUN DNS 状态目录 {} 失败：{e}", parent.display());
            self.persist_failed = true;
            return;
        }
        match serde_json::to_string_pretty(&self.state) {
            Ok(content) => {
                if let Err(e) = fs::write(&self.path, content) {
                    warn!("写入 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
                    self.persist_failed = true;
                } else {
                    self.persist_failed = false;
                }
            }
            Err(e) => {
                warn!("序列化 TUN DNS 状态失败：{e}");
                self.persist_failed = true;
            }
        }
    }

    fn remove_state_file(&mut self) {
        if self.persist_failed {
            debug!(
                "TUN DNS 状态文件此前写入失败，无需清理：{}",
                self.path.display()
            );
        }
        remove_file_if_exists(&self.path);
        self.state.records.clear();
    }
}

fn dns_state_file_path(configured_file: Option<&str>) -> PathBuf {
    if let Some(path) = std::env::var_os("PPAASS_TUN_DNS_STATE") {
        return PathBuf::from(path);
    }

    let configured_file = configured_file
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or(DNS_STATE_FILE_NAME);
    let path = PathBuf::from(configured_file);
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn remove_file_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => debug!("已删除 TUN DNS 状态文件：{}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("删除 TUN DNS 状态文件 {} 失败：{e}", path.display()),
    }
}

fn current_process_is_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg("$p = Get-Process -Id $args[0] -ErrorAction SilentlyContinue; if ($p) { exit 0 } else { exit 1 }")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(not(windows))]
    {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}
