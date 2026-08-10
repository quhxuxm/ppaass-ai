use super::*;
use std::process::Command;
use tracing::debug;

pub(super) fn system_dns_server_ips() -> Vec<IpAddr> {
    let script = r#"
Get-DnsClientServerAddress |
  ForEach-Object { $_.ServerAddresses } |
  Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
"#;
    match run_powershell(script, &[]) {
        Ok(output) => parse_dns_server_ips(&output),
        Err(e) => {
            debug!("读取 Windows 系统 DNS 服务器失败：{e}");
            Vec::new()
        }
    }
}

fn run_powershell(script: &str, args: &[&str]) -> std::io::Result<String> {
    debug!("运行 PowerShell DNS 脚本");
    let command = format!("& {{\n{script}\n}}");
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("PowerShell DNS 脚本退出状态 {}", output.status)
        } else {
            stderr
        };
        return Err(std::io::Error::other(message));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
