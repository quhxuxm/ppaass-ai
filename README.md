# PPAASS - Secure Proxy Application

A high-performance, secure proxy application built with Rust, featuring HTTP and SOCKS5 protocol support with end-to-end encryption.

## Features

- **Dual Protocol Support**: Automatically detects and handles both HTTP and SOCKS5 protocols
- **End-to-End Encryption**: RSA for key exchange, AES-256-GCM for data encryption
- **Multi-User Support**: Each user has their own RSA key pair with bandwidth limits
- **Connection Pooling**: Efficient connection reuse with multiplexing
- **REST API**: Comprehensive API for user management and monitoring
- **Bandwidth Management**: Per-user bandwidth limits and monitoring
- **Secure DNS Resolution**: DNS resolution performed on proxy side
- **Production Ready**: Built with tokio, includes health monitoring and graceful shutdown

## Architecture

The application consists of four main components:

1. **Agent**: Runs on client machine, forwards traffic to proxy
2. **Proxy**: Server-side component that connects to target servers
3. **Protocol**: Shared protocol definition and crypto implementation
4. **Common**: Shared utilities and error types

## Quick Start

### Prerequisites

- Rust 1.93.0 or later with edition 2024
- OpenSSL or compatible crypto library

### Build

```bash
# Build all components
cargo build --release

# Build specific component
cargo build --release -p agent
cargo build --release -p proxy
```

### Configuration

1. Copy example configurations:
```bash
mkdir -p config keys
cp config/agent.toml.example config/agent.toml
cp config/proxy.toml.example config/proxy.toml
```

2. Start the proxy server:
```bash
cargo run --release -p proxy -- --config config/proxy.toml
```

3. Add a user via API:
```bash
curl -X POST http://localhost:8081/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "bandwidth_limit_mbps": 100,
    "max_connections": 50
  }'
```

4. Save the returned private key to `keys/user1.pem`

5. Update `config/agent.toml` with your username and key path

6. Start the agent:
```bash
cargo run --release -p agent -- --config config/agent.toml
```

7. Configure your applications to use the proxy at `127.0.0.1:1080`

## REST API

The proxy exposes a REST API on port 8081 (configurable):

### Add User
```bash
POST /api/users
{
  "username": "user1",
  "bandwidth_limit_mbps": 100,
  "max_connections": 50
}
```

### Remove User
```bash
DELETE /api/users
{
  "username": "user1"
}
```

### List Users
```bash
GET /api/users
```

### Get Bandwidth Statistics
```bash
GET /api/stats/bandwidth
```

### Health Check
```bash
GET /health
```

### Get Configuration
```bash
GET /api/config
```

### Update Configuration
```bash
PUT /api/config
{
  "listen_addr": "0.0.0.0:8080",
  "api_addr": "0.0.0.0:8081",
  ...
}
```

## Configuration

### Agent Configuration (`config/agent.toml`)

```toml
listen_addr = "127.0.0.1:1080"      # Local proxy address
proxy_addr = "proxy.example.com:8080" # Remote proxy address
username = "user1"                    # Your username
password = "password123"              # Your password
private_key_path = "keys/user1.pem"  # Path to your RSA private key
pool_size = 10                        # Connection pool size
pool_timeout_secs = 30                # Connection timeout
console_port = 6669                   # Optional: tokio-console port
```

### Proxy Configuration (`config/proxy.toml`)

```toml
listen_addr = "0.0.0.0:8080"              # Proxy listen address
api_addr = "0.0.0.0:8081"                 # API listen address
users_config_path = "config/users.toml"   # Users configuration file
keys_dir = "keys"                         # Directory for storing keys
max_connections_per_user = 100            # Default max connections
console_port = 6670                       # Optional: tokio-console port
```

## Security

- **RSA-2048**: Used for secure key exchange
- **AES-256-GCM**: Used for data encryption with authenticated encryption
- **Timestamp Validation**: Prevents replay attacks (5-minute tolerance)
- **Secure Key Storage**: Private keys stored securely on disk
- **Per-User Authentication**: Each user has unique credentials

## Performance

- **Async I/O**: Built on tokio for high concurrency
- **Connection Pooling**: Reuses connections for better performance
- **Multiplexing**: Multiple streams over single connection
- **Zero-Copy**: Efficient buffer management with bytes crate

### Performance Testing

The project includes comprehensive performance testing tools:

```bash
# Start mock target servers
./run-tests.sh mock-target

# Run performance tests (in another terminal)
./run-tests.sh performance 100 60

# View HTML report with charts
open performance-report-*.html
```

See `tests/README.md` for detailed testing documentation.

## Monitoring

### Tokio Console

Enable tokio-console for detailed runtime monitoring:

1. Set `console_port` in configuration
2. Build with console feature: `cargo build --release --features console`
3. Connect with tokio-console: `tokio-console http://localhost:6669`

### Logging

Set log level via environment variable:
```bash
RUST_LOG=info cargo run -p proxy
RUST_LOG=debug cargo run -p agent
```

## Development

### Project Structure

```
ppaass-ai/
├── agent/          # Client-side agent
├── proxy/          # Server-side proxy
├── protocol/       # Shared protocol definitions
├── common/         # Shared utilities
├── tests/          # Integration and performance tests
├── config/         # Configuration files
├── keys/           # RSA keys (gitignored)
└── doc/           # Documentation
```

### Running Tests

```bash
# Unit tests
cargo test --workspace

# Integration and performance tests
./run-tests.sh all

# See tests/README.md for detailed testing documentation
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Lint code
cargo clippy --workspace -- -D warnings

# Check for security issues
cargo audit
```

## Troubleshooting

### Connection Issues

1. Check firewall settings
2. Verify proxy server is running: `curl http://proxy:8081/health`
3. Check logs for authentication errors
4. Ensure private key matches user's public key

### Performance Issues

1. Increase pool size in agent configuration
2. Check bandwidth limits
3. Monitor with tokio-console
4. Review network latency

### Authentication Failures

1. Verify private key format and permissions
2. Check username matches proxy configuration
3. Ensure timestamp synchronization between client and server
4. Review proxy logs for detailed error messages

## License

MIT

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## Acknowledgments

Built with these excellent Rust crates:
- tokio - Async runtime
- hyper - HTTP implementation
- fast-socks5 - SOCKS5 protocol
- rsa, aes-gcm - Cryptography
- axum - Web framework for API
- deadpool - Connection pooling
