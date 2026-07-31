//! Proxy Entry CLI 薄入口。

use anyhow::Result;
use clap::Parser;
#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;
use proxy_entry::config::ProxyConfig;

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "proxy-entry.toml")]
    config: String,

    /// 覆盖监听地址
    #[arg(short, long)]
    listen: Option<String>,

    /// 覆盖日志级别（trace、debug、info、warn、error）
    #[arg(long)]
    log_level: Option<String>,

    /// 覆盖日志目录
    #[arg(long)]
    log_dir: Option<String>,

    /// 覆盖日志文件名
    #[arg(long)]
    log_file: Option<String>,

    /// 覆盖运行时工作线程数
    #[arg(long)]
    runtime_threads: Option<usize>,

    /// 覆盖 proxy 连接目标服务器时使用的出站网络设备名
    #[arg(long)]
    outbound_interface: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 先加载配置文件，再让命令行参数覆盖配置项。
    // 这样同一份 proxy-entry.toml 可用于生产默认值，本地调试时只覆盖少量参数。
    let mut config = ProxyConfig::load(&args.config)?;

    // 使用命令行参数覆盖配置。
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }
    if let Some(log_level) = args.log_level {
        config.log_level = log_level;
    }
    if let Some(log_dir) = args.log_dir {
        config.log_dir = Some(log_dir);
    }
    if let Some(log_file) = args.log_file {
        config.log_file = log_file;
    }
    if let Some(runtime_threads) = args.runtime_threads {
        config.runtime_threads = Some(runtime_threads);
    }
    if let Some(outbound_interface) = args.outbound_interface {
        config.outbound_interface = Some(outbound_interface);
    }

    proxy_entry::run(config)
}
