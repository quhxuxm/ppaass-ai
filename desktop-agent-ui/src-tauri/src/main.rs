#![cfg_attr(windows, windows_subsystem = "windows")]

mod agent;
mod app;
mod auth;
mod config;
mod diagnostics;
mod logging;
#[cfg(target_os = "macos")]
mod macos_helper;
mod models;
mod network;
mod packet_capture;
mod process_util;
mod runtime;
mod telemetry;
mod tray;
#[cfg(windows)]
mod windows_service;

fn main() {
    app::run();
}
