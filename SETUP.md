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

### Step 1: Start the Proxy Server

1. Edit `config/proxy.toml` if needed:

```toml
listen_addr = "0.0.0.0:8080"
users_path = "config/users.toml"
```

2. Start the proxy server:

```bash
# On Windows
.\target\release\proxy.exe --config config\proxy.toml

# On Linux/macOS
./target/release/proxy --config config/proxy.toml
```

#### Alternative: Use startup scripts (same-folder deployment)

If you deploy the binaries and configs alongside the scripts, use:

```bash
# Proxy on Linux
./start-proxy.sh
```

```powershell
# Proxy on Windows (dev helper)
.\start-proxy.bat
```

### Step 2: Add a User in `users.toml`

Add the user's public key and optional bandwidth limit to the proxy users file:

```toml
[users.myuser]
username = "myuser"
public_key_pem = """
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
"""
bandwidth_limit_mbps = 100
```

### Step 3: Configure the Agent

1. Save the matching private key to `keys/myuser.pem`

2. Edit `config/agent.toml`:

```toml
listen_addr = "127.0.0.1:1080"
proxy_addr = "your.proxy.server:8080"  # Change to your proxy address
username = "myuser"
private_key_path = "keys/myuser.pem"
pool_size = 10
connection_timeout_secs = 30
```

3. Start the agent:

```bash
# On Windows
.\target\release\desktop-agent.exe --config config\agent.toml

# On Linux/macOS
./target/release/desktop-agent --config config/agent.toml
```

#### Alternative: Use startup scripts (same-folder deployment)

If you deploy the binaries and configs alongside the scripts, use:

```powershell
# Agent on Windows
.\start-agent.bat
```

```bash
# Agent on macOS
./start-agent.sh
```

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
    - Check that the user exists in the proxy `users.toml`

### Performance Issues

1. **Increase pool size:**
    - Edit `pool_size` in `config/agent.toml`
    - Recommended: 10-50 depending on load

2. **Check bandwidth limits:**
    - Review user bandwidth limits in `users.toml`

## Security Notes

- **Private Keys:** Keep private keys secure and never share them
- **Configuration Files:** Protect configuration files with appropriate permissions
- **Network:** Use firewall rules to restrict access to the proxy
## Advanced Configuration

### Multiple Users

You can add multiple users with different bandwidth limits by adding multiple `[users.<name>]` sections to `users.toml`.

## Support

For issues and questions:

1. Check logs with `RUST_LOG=debug`
2. Review the main README.md
3. Check firewall and network configuration
4. Verify all configuration files are correct

## Quick Reference

**Start Proxy:**

```bash
./target/release/proxy --config config/proxy.toml
```

**Start Agent:**

```bash
./target/release/desktop-agent --config config/agent.toml
```

**Test Connection:**

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```
