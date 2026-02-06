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
api_addr = "0.0.0.0:8081"
users_config_path = "config/users.toml"
keys_dir = "keys"
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

### Step 2: Add a User via API

Use curl or any HTTP client:

```bash
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "myuser",
    "bandwidth_limit_mbps": 100
  }'
```

The response will include:

- `private_key`: Save this to `keys/myuser.pem`
- `public_key`: Automatically saved in the proxy configuration

### Step 3: Configure the Agent

1. Save the private key from the previous step to `keys/myuser.pem`

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
.\target\release\agent.exe --config config\agent.toml

# On Linux/macOS
./target/release/agent --config config/agent.toml
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

## API Usage

### Check Health

```bash
curl http://localhost:8081/health
```

### List Users

```bash
curl http://localhost:8081/api/users
```

### Get Bandwidth Statistics

```bash
curl http://localhost:8081/api/stats/bandwidth
```

### Remove User

```bash
curl -X DELETE http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "myuser"}'
```

## Troubleshooting

### Connection Issues

1. **Check if proxy is running:**

```bash
curl http://localhost:8081/health
```

2. **Check firewall settings:**
    - Ensure ports 8080 and 8081 are open on the proxy server
    - Ensure port 1080 is available on the client machine

3. **Check logs:**
    - Agent and proxy output detailed logs
    - Set log level: `RUST_LOG=debug ./target/release/agent`

### Authentication Issues

1. **Verify private key:**
    - Ensure the private key file exists and is readable
    - Verify the key format (should be PEM format)

2. **Check user configuration:**
    - Verify the username in agent config matches the proxy
    - Check that the user exists: `curl http://localhost:8081/api/users`

### Performance Issues

1. **Increase pool size:**
    - Edit `pool_size` in `config/agent.toml`
    - Recommended: 10-50 depending on load

2. **Check bandwidth limits:**
    - Review user bandwidth limits in the API
    - Monitor with: `curl http://localhost:8081/api/stats/bandwidth`

## Security Notes

- **Private Keys:** Keep private keys secure and never share them
- **Configuration Files:** Protect configuration files with appropriate permissions
- **Network:** Use firewall rules to restrict access to the proxy
- **HTTPS:** Consider putting the API behind a reverse proxy with HTTPS

## Advanced Configuration

### Enable tokio-console (for debugging)

1. Build with console feature:

```bash
cargo build --release --features console -p agent
cargo build --release --features console -p proxy
```

2. Add to config:

```toml
console_port = 6669  # for agent
console_port = 6670  # for proxy
```

3. Connect with tokio-console:

```bash
tokio-console http://localhost:6669
```

### Multiple Users

You can add multiple users with different bandwidth limits:

```bash
# Add user1 with 100 Mbps limit
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "bandwidth_limit_mbps": 100}'

# Add user2 with 50 Mbps limit
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "user2", "bandwidth_limit_mbps": 50}'
```

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
./target/release/agent --config config/agent.toml
```

**Add User:**

```bash
curl -X POST http://localhost:8081/api/users -H "Content-Type: application/json" -d '{"username": "user1"}'
```

**Check Status:**

```bash
curl http://localhost:8081/health
```

**Test Connection:**

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```
