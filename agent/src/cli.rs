use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/agent.toml")]
    pub config: String,

    /// Override listen address
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Override proxy server address
    #[arg(short, long)]
    pub proxy: Option<String>,

    /// Override username
    #[arg(short, long)]
    pub username: Option<String>,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,

    /// Override log directory
    #[arg(long)]
    pub log_dir: Option<String>,

    /// Override log file name
    #[arg(long)]
    pub log_file: Option<String>,

    /// Override number of runtime worker threads
    #[arg(long)]
    pub runtime_threads: Option<usize>,
}
