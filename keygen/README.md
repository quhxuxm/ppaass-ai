# RSA Key Generator for PPaass

This utility generates RSA-2048 key pairs for use with the PPaass proxy system.

## Usage

```powershell
# Generate new RSA keys
cargo run -p keygen --release

# Or run the compiled binary directly
.\target\release\keygen.exe
```

## Output

The tool generates two sets of RSA-2048 key pairs:

1. **Proxy Server Keys**: Public and private keys for the proxy server
2. **Agent User Keys**: Public and private keys for an agent user

## How to Use the Generated Keys

### Step 1: Run the Key Generator

```powershell
cd D:\Workspace\GitHub\ppaass-ai
cargo run -p keygen --release
```

### Step 2: Copy Keys to Configuration Files

The output will show you exactly what to copy where:

1. **For proxy.toml**:
   - Copy `PROXY SERVER PUBLIC KEY` to `rsa_public_key` field
   - Copy `PROXY SERVER PRIVATE KEY` to `rsa_private_key` field

2. **For agent.toml**:
   - Copy `PROXY SERVER PUBLIC KEY` to `proxy_rsa_public_key` field
   - Copy `AGENT USER PUBLIC KEY` to `user.rsa_public_key` field
   - Copy `AGENT USER PRIVATE KEY` to `user.rsa_private_key` field

### Example Configuration

**proxy.toml:**
```toml
rsa_public_key = """-----BEGIN PUBLIC KEY-----
[paste PROXY SERVER PUBLIC KEY here]
-----END PUBLIC KEY-----"""

rsa_private_key = """-----BEGIN PRIVATE KEY-----
[paste PROXY SERVER PRIVATE KEY here]
-----END PRIVATE KEY-----"""
```

**agent.toml:**
```toml
proxy_rsa_public_key = """-----BEGIN PUBLIC KEY-----
[paste PROXY SERVER PUBLIC KEY here]
-----END PUBLIC KEY-----"""

[user]
username = "your_username"
password = "your_password"
rsa_public_key = """-----BEGIN PUBLIC KEY-----
[paste AGENT USER PUBLIC KEY here]
-----END PUBLIC KEY-----"""
rsa_private_key = """-----BEGIN PRIVATE KEY-----
[paste AGENT USER PRIVATE KEY here]
-----END PRIVATE KEY-----"""
```

## Security Notes

- **NEVER share private keys** - Keep them secure!
- The proxy server's public key must be shared with all agents
- Each agent user should have their own unique key pair
- Generate new keys periodically for enhanced security
- Store private keys with appropriate file permissions (e.g., chmod 600 on Linux)

## Key Format

The generated keys are in PEM format:
- Public keys: PKCS#8 format
- Private keys: PKCS#8 format

These are standard RSA key formats compatible with most cryptographic libraries.

## Regenerating Keys

You can run this tool multiple times to generate new keys. Each run produces completely new, randomly generated key pairs.

To update keys in a running system:
1. Generate new keys with this tool
2. Update configuration files
3. Restart the proxy server and agents
