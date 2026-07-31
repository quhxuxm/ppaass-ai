# PPAASS Setup Guide

This guide will help you set up and run the PPAASS proxy application.

## Prerequisites

- Rust 1.93.0 or later
- Windows, Linux, or macOS
- Network connectivity

## Installation

### 1. Clone or Download

If you received this as source code, ensure all files are in place.

### 2. Build the Project

#### On Windows:

```powershell
.\build.ps1
```

#### On Linux/macOS:

```bash
chmod +x build.sh
./build.sh
```

Or build directly with cargo:

```bash
cargo build --release --workspace
```

### 3. Create Configuration Directories

```bash
# Create necessary directories
mkdir -p config keys
```

## Configuration

### Step 1: Start Proxy Registry

Proxy Registry owns SQLite and exposes a separate loopback control listener:

```bash
export PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD="replace-with-a-strong-password"
export PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET="replace-with-at-least-32-random-bytes"
export PPAASS_PROXY_REGISTRY_CONTROL_TOKEN="replace-with-at-least-32-random-bytes"
umask 077
mkdir -p data
printf '%s' "$PPAASS_PROXY_REGISTRY_CONTROL_TOKEN" > data/proxy-control-token
cargo run --release -p proxy-registry -- \
  --listen 127.0.0.1:8787 \
  --control-listen 127.0.0.1:8797
```

### Step 2: Start Proxy Entry

1. Edit `config/proxy-entry.toml` if needed:

```toml
listen_addr = "0.0.0.0:8080"
entry_id = "entry-local"
registry_control_url = "http://127.0.0.1:8797"
registry_control_token_path = "data/proxy-control-token"
```

2. Start Proxy Entry:

```bash
# On Windows
.\target\release\proxy-entry.exe --config config\proxy-entry.toml

# On Linux/macOS
./target/release/proxy-entry --config config/proxy-entry.toml
```

#### Alternative: Use startup scripts (same-folder deployment)

If you deploy the binaries and configs alongside the scripts, use:

```bash
# Proxy Entry on Linux
./start-proxy-entry.sh
```

```powershell
# Proxy Entry on Windows (dev helper)
.\start-proxy-entry.bat
```

### Step 3: Register and Approve a User

Register a normal account, submit a key request, and approve it from the administrator console with
an expiration time. Proxy Registry creates the managed key pair and persists it. Proxy Entry receives
only public authorization snapshots over the authenticated control API.

### Step 4: Configure the Agent

Edit `config/agent.toml` with the Proxy Registry endpoint, then sign in from the Agent UI. Proxy Registry
assigns the runtime Proxy addresses; they are not stored in `agent.toml`. The Agent downloads and
applies the approved managed credential automatically.

```toml
listen_addr = "127.0.0.1:1080"
connection_timeout_secs = 30

[yamux.tcp]
sessions = 5
max_streams_per_session = 128

[yamux.udp]
sessions = 5
max_streams_per_session = 128
```

3. Open the Desktop Agent UI, sign in, and start the Agent there. The product
   `desktop-agent` binary no longer accepts a Proxy address or starts normal traffic by itself.

#### TUN helper startup behavior

Desktop TUN mode needs permission to create the TUN device, install routes, and
on macOS install temporary PF rules that capture DNS traffic without changing
the system DNS servers.
On macOS, `start-agent.sh` and `start-agent.command` install the existing `desktop-agent` binary as a privileged helper-mode service when `[tun] enabled = true` and `macos_helper_enabled = true`. Later TUN starts use the helper socket instead of prompting for sudo every time. No separate helper binary is built or installed. To remove the installed service:

```bash
./scripts/uninstall-tun-helper-unix.sh
```

On Windows, `start-agent.bat` creates a highest-privilege scheduled task the first time TUN mode is started. That first install may show UAC once; later starts use the task instead of relaunching the agent through UAC every time.

#### Alternative: Use startup scripts (same-folder deployment)

Agent traffic is started from the authenticated Desktop Agent UI. Legacy standalone startup
scripts are not an authentication substitute.

### Step 4: Configure Your Applications

Configure your applications to use the proxy:

**For SOCKS5:**

- Host: 127.0.0.1
- Port: 1080
- Type: SOCKS5

**For HTTP:**

- Proxy: http://127.0.0.1:1080

## Testing

### Test with curl (HTTP):

```bash
curl -x http://127.0.0.1:1080 http://example.com
```

### Test with curl (SOCKS5):

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

## Troubleshooting

### Connection Issues

1. **Check if proxy is running:**

Use `netstat`, `ss`, or the process manager to verify the proxy is listening on its configured port.

2. **Check firewall settings:**
    - Ensure the proxy listen port is open on the proxy server
    - Ensure port 1080 is available on the client machine

3. **Check logs:**
    - Agent and proxy output detailed logs
    - Set log level: `RUST_LOG=debug ./target/release/desktop-agent`

### Authentication Issues

1. **Verify private key:**
    - Ensure the private key file exists and is readable
    - Verify the key format (should be PEM format)

2. **Check user configuration:**
    - Verify the username in agent config matches the proxy
    - Check that the account has an active approved profile in the Proxy Registry SQLite database

### Performance Issues

1. **Tune Yamux session counts:**
    - Edit `[yamux.tcp].sessions` and `[yamux.udp].sessions` in `config/agent.toml`
    - TCP relay and UDP relay use separate raw Yamux session pools

## Security Notes

- **Private Keys:** Keep private keys secure and never share them
- **Configuration Files:** Protect configuration files with appropriate permissions
- **Network:** Use firewall rules to restrict access to the proxy
## Advanced Configuration

### Multiple Users

Create and approve additional accounts from the Proxy Registry administrator console.

## Support

For issues and questions:

1. Check logs with `RUST_LOG=debug`
2. Review the main README.md
3. Check firewall and network configuration
4. Verify all configuration files are correct

## Quick Reference

**Start Proxy Entry:**

```bash
./target/release/proxy-entry --config config/proxy-entry.toml
```

**Start Agent:**

Open the Desktop Agent UI, sign in, and use its Start control.

**Test Connection:**

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```
