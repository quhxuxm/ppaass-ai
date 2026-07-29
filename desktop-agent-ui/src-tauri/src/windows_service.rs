#![cfg(windows)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown as TcpShutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tempfile::Builder as TempFileBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use tokio::task;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{
    agent_state, clear_packet_capture_runtime_local, packet_capture_runtime_status_local,
    set_packet_capture_runtime_enabled_local, start_agent_inner, stop_embedded_agent,
};
use crate::auth::{load_persisted_agent_login_from_dir, set_windows_restricted_acl};
use crate::logging::UiLogBuffer;
use crate::models::{
    AgentAuthAccountStatus, AgentState, ServiceRequest, ServiceResponse, VerifiedProxyAuthStatus,
};
use crate::runtime::AgentRuntime;
use crate::telemetry::agent_traffic_snapshot;

pub(crate) const SERVICE_ARG: &str = "--ppaass-agent-service";
pub(crate) const INSTALL_SERVICE_ARG: &str = "--ppaass-install-service";
pub(crate) const SERVICE_CONFIG_ROOT_ARG: &str = "--ppaass-service-config-root";

const SERVICE_NAME: &str = "PPAASSAgentService";
const SERVICE_DISPLAY_NAME: &str = "PPAASS Agent Service";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICE_IPC_ADDR: &str = "127.0.0.1:17981";
const SERVICE_IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const SERVICE_IPC_IO_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_SERVICE_IPC_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_SERVICE_IPC_RESPONSE_BYTES: u64 = 1024 * 1024;
const SERVICE_SESSION_FILE_NAME: &str = "service-session.json";
const SERVICE_SESSION_FILE_VERSION: u8 = 1;
const SERVICE_SESSION_TOKEN_BYTES: usize = 32;
const SERVICE_SESSION_TOKEN_HEX_LEN: usize = SERVICE_SESSION_TOKEN_BYTES * 2;
const MAX_SERVICE_SESSION_FILE_BYTES: u64 = 4 * 1024;
const SERVICE_DESIRED_STATE_FILE_NAME: &str = "service-runtime-state.json";
const SERVICE_DESIRED_STATE_FILE_VERSION: u8 = 1;
const MAX_SERVICE_DESIRED_STATE_FILE_BYTES: u64 = 1024;
const MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE: &str = "proxy-identity-public.pem";

static SERVICE_CONFIG_ROOT: OnceLock<PathBuf> = OnceLock::new();
static UI_SERVICE_SESSION_TOKEN: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

mod client;
mod installation;
mod path_validation;
mod request_handler;
mod runtime_service;
mod session;
mod state_store;

pub(crate) use client::*;
pub(crate) use installation::*;
pub(crate) use path_validation::*;
pub(crate) use request_handler::*;
pub(crate) use runtime_service::*;
pub(crate) use session::*;
pub(crate) use state_store::*;

#[cfg(test)]
mod tests;
