use crate::config::AgentConfig;
use ratatui::layout::Rect;

pub(crate) const MAX_TRAFFIC_ROWS: usize = 400;
pub(crate) const TRENDS_LEFT_DEFAULT_PERCENT: u16 = 40;
pub(crate) const TRENDS_LEFT_MIN_PERCENT: u16 = 20;
pub(crate) const TRENDS_LEFT_MAX_PERCENT: u16 = 70;
pub(crate) const LOG_HEIGHT_DEFAULT_PERCENT: u16 = 30;
pub(crate) const LOG_HEIGHT_MIN_PERCENT: u16 = 15;
pub(crate) const LOG_HEIGHT_MAX_PERCENT: u16 = 70;
pub(crate) const TABS_HEIGHT: u16 = 3;
pub(crate) const STATUS_HEIGHT: u16 = 4;
pub(crate) const FOOTER_HEIGHT: u16 = 5;
pub(crate) const TOKIO_TASKS_WIDTH_PERCENT: u16 = 68;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentLayoutRects {
    pub(crate) body: Rect,
    pub(crate) top: Rect,
    pub(crate) logs: Rect,
    pub(crate) trends: Rect,
    pub(crate) sessions: Rect,
    pub(crate) sessions_table: Rect,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TokioConsoleLayoutRects {
    pub(crate) summary: Rect,
    pub(crate) tasks_table: Rect,
    pub(crate) task_details: Rect,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConfigLayoutRects {
    pub(crate) summary: Rect,
    pub(crate) fields_table: Rect,
    pub(crate) editor: Rect,
}

#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokioConsoleState {
    Disabled,
    Unsupported,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppTab {
    Agent,
    TokioConsole,
    Config,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ConfigFieldKey {
    ListenAddr,
    ProxyAddrs,
    Username,
    PrivateKeyPath,
    AsyncRuntimeStackSizeMb,
    PoolSize,
    ConnectTimeoutSecs,
    ConsolePort,
    LogLevel,
    LogDir,
    LogFile,
    LogBufferLines,
    RuntimeThreads,
}

impl ConfigFieldKey {
    pub(crate) const ALL: [ConfigFieldKey; 13] = [
        ConfigFieldKey::ListenAddr,
        ConfigFieldKey::ProxyAddrs,
        ConfigFieldKey::Username,
        ConfigFieldKey::PrivateKeyPath,
        ConfigFieldKey::AsyncRuntimeStackSizeMb,
        ConfigFieldKey::PoolSize,
        ConfigFieldKey::ConnectTimeoutSecs,
        ConfigFieldKey::ConsolePort,
        ConfigFieldKey::LogLevel,
        ConfigFieldKey::LogDir,
        ConfigFieldKey::LogFile,
        ConfigFieldKey::LogBufferLines,
        ConfigFieldKey::RuntimeThreads,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            ConfigFieldKey::ListenAddr => "listen_addr",
            ConfigFieldKey::ProxyAddrs => "proxy_addrs",
            ConfigFieldKey::Username => "username",
            ConfigFieldKey::PrivateKeyPath => "private_key_path",
            ConfigFieldKey::AsyncRuntimeStackSizeMb => "async_runtime_stack_size_mb",
            ConfigFieldKey::PoolSize => "pool_size",
            ConfigFieldKey::ConnectTimeoutSecs => "connect_timeout_secs",
            ConfigFieldKey::ConsolePort => "console_port",
            ConfigFieldKey::LogLevel => "log_level",
            ConfigFieldKey::LogDir => "log_dir",
            ConfigFieldKey::LogFile => "log_file",
            ConfigFieldKey::LogBufferLines => "log_buffer_lines",
            ConfigFieldKey::RuntimeThreads => "runtime_threads",
        }
    }

    pub(crate) fn value(self, config: &AgentConfig) -> String {
        match self {
            ConfigFieldKey::ListenAddr => config.listen_addr.clone(),
            ConfigFieldKey::ProxyAddrs => config.proxy_addrs.join(", "),
            ConfigFieldKey::Username => config.username.clone(),
            ConfigFieldKey::PrivateKeyPath => config.private_key_path.clone(),
            ConfigFieldKey::AsyncRuntimeStackSizeMb => {
                config.async_runtime_stack_size_mb.to_string()
            }
            ConfigFieldKey::PoolSize => config.pool_size.to_string(),
            ConfigFieldKey::ConnectTimeoutSecs => config.connect_timeout_secs.to_string(),
            ConfigFieldKey::ConsolePort => config
                .console_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            ConfigFieldKey::LogLevel => config.log_level.clone(),
            ConfigFieldKey::LogDir => config.log_dir.clone().unwrap_or_default(),
            ConfigFieldKey::LogFile => config.log_file.clone(),
            ConfigFieldKey::LogBufferLines => config.log_buffer_lines.to_string(),
            ConfigFieldKey::RuntimeThreads => config
                .runtime_threads
                .map(|threads| threads.to_string())
                .unwrap_or_default(),
        }
    }

    pub(crate) fn apply(
        self,
        config: &mut AgentConfig,
        input: &str,
    ) -> std::result::Result<(), String> {
        let value = input.trim();
        match self {
            ConfigFieldKey::ListenAddr => {
                if value.is_empty() {
                    return Err("listen_addr cannot be empty".to_string());
                }
                config.listen_addr = value.to_string();
            }
            ConfigFieldKey::ProxyAddrs => {
                let addrs = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if addrs.is_empty() {
                    return Err("proxy_addrs requires at least one address".to_string());
                }
                config.proxy_addrs = addrs;
            }
            ConfigFieldKey::Username => {
                if value.is_empty() {
                    return Err("username cannot be empty".to_string());
                }
                config.username = value.to_string();
            }
            ConfigFieldKey::PrivateKeyPath => {
                if value.is_empty() {
                    return Err("private_key_path cannot be empty".to_string());
                }
                config.private_key_path = value.to_string();
            }
            ConfigFieldKey::AsyncRuntimeStackSizeMb => {
                let parsed = value.parse::<usize>().map_err(|_| {
                    "async_runtime_stack_size_mb must be a positive integer".to_string()
                })?;
                if parsed == 0 {
                    return Err("async_runtime_stack_size_mb must be > 0".to_string());
                }
                config.async_runtime_stack_size_mb = parsed;
            }
            ConfigFieldKey::PoolSize => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "pool_size must be a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("pool_size must be > 0".to_string());
                }
                config.pool_size = parsed;
            }
            ConfigFieldKey::ConnectTimeoutSecs => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "connect_timeout_secs must be an integer".to_string())?;
                if parsed == 0 {
                    return Err("connect_timeout_secs must be > 0".to_string());
                }
                config.connect_timeout_secs = parsed;
            }
            ConfigFieldKey::ConsolePort => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.console_port = None;
                } else {
                    let parsed = value.parse::<u16>().map_err(|_| {
                        "console_port must be a number between 1 and 65535".to_string()
                    })?;
                    if parsed == 0 {
                        return Err("console_port must be between 1 and 65535".to_string());
                    }
                    config.console_port = Some(parsed);
                }
            }
            ConfigFieldKey::LogLevel => {
                if value.is_empty() {
                    return Err("log_level cannot be empty".to_string());
                }
                config.log_level = value.to_string();
            }
            ConfigFieldKey::LogDir => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.log_dir = None;
                } else {
                    config.log_dir = Some(value.to_string());
                }
            }
            ConfigFieldKey::LogFile => {
                if value.is_empty() {
                    return Err("log_file cannot be empty".to_string());
                }
                config.log_file = value.to_string();
            }
            ConfigFieldKey::LogBufferLines => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "log_buffer_lines must be a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("log_buffer_lines must be > 0".to_string());
                }
                config.log_buffer_lines = parsed;
            }
            ConfigFieldKey::RuntimeThreads => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.runtime_threads = None;
                } else {
                    let parsed = value
                        .parse::<usize>()
                        .map_err(|_| "runtime_threads must be a positive integer".to_string())?;
                    if parsed == 0 {
                        return Err("runtime_threads must be > 0".to_string());
                    }
                    config.runtime_threads = Some(parsed);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleTaskSort {
    Polls,
    Wakes,
    Name,
    Id,
}

impl ConsoleTaskSort {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Polls => Self::Wakes,
            Self::Wakes => Self::Name,
            Self::Name => Self::Id,
            Self::Id => Self::Polls,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Polls => "polls",
            Self::Wakes => "wakes",
            Self::Name => "name",
            Self::Id => "id",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConsoleTaskView {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) kind: String,
    #[cfg_attr(not(feature = "console"), allow(dead_code))]
    pub(crate) metadata_id: Option<u64>,
    pub(crate) wakes: u64,
    pub(crate) polls: u64,
    pub(crate) self_wakes: u64,
    pub(crate) is_live: bool,
}

#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub(crate) struct ConsoleSnapshot {
    pub(crate) temporality: String,
    pub(crate) tasks: Vec<ConsoleTaskView>,
    pub(crate) live_tasks: usize,
    pub(crate) dropped_task_events: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConsoleTaskDetailsView {
    pub(crate) task_id: u64,
    pub(crate) updated_at_secs: Option<u64>,
    pub(crate) poll_histogram_max_ns: Option<u64>,
    pub(crate) poll_histogram_high_outliers: u64,
    pub(crate) poll_histogram_highest_outlier_ns: Option<u64>,
    pub(crate) scheduled_histogram_max_ns: Option<u64>,
    pub(crate) scheduled_histogram_high_outliers: u64,
    pub(crate) scheduled_histogram_highest_outlier_ns: Option<u64>,
}
