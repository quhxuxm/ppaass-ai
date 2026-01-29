# PPaass - Secure Proxy Application

A high-performance, secure proxy application written in Rust with separate agent (client) and proxy (server) components.

## Features

- **Dual Protocol Support**: HTTP and SOCKS5 proxy protocols on the agent side
- **End-to-End Encryption**: RSA key exchange + AES-256-GCM for data encryption
- **Multi-User Support**: Each user has separate credentials and RSA keys
- **Bandwidth Management**: Configurable bandwidth limits per user
- **Connection Pooling**: Efficient connection reuse on agent side
- **REST API**: Comprehensive management API on proxy side
- **Real-time Monitoring**: Built-in support for tokio-console

## Architecture

```
┌─────────────┐         Encrypted         ┌──────────────┐         Plain        ┌────────────┐
│   Client    │ ────▶ │    Agent     │ ────▶ │    Proxy     │ ────▶ │   Target   │
│ Application │       │ (HTTP/SOCKS5) │       │   (Server)   │       │   Server   │
└─────────────┘         └──────────────┘         └──────────────┘         └────────────┘
```

## Components

### Common Library
Shared functionality:
- Cryptography (RSA, AES-256-GCM)
- Protocol definitions
- Bandwidth limiting and tracking
- Error handling

### Agent (Client Side)
- HTTP proxy server (default: 127.0.0.1:8080)
- SOCKS5 proxy server (default: 127.0.0.1:1080)
- Connection pool to proxy server
- Automatic encryption of all traffic

### Proxy (Server Side)
- Relay server for encrypted traffic
- REST API for management
- User authentication and authorization
- Bandwidth limiting per user
- Session management

## Getting Started

### Prerequisites

- Rust 1.93.0 or later with edition 2024
- OpenSSL development libraries (for cryptography)

### Building

```bash
# Build all components
cargo build --release

# Build specific component
cargo build -p agent --release
cargo build -p proxy --release
```

### Configuration

The project includes ready-to-use configuration templates:
- `agent.toml` - Agent configuration template with real RSA keys
- `proxy.toml` - Proxy configuration template with real RSA keys
- `agent.example.toml` - Additional example
- `proxy.example.toml` - Additional example

For detailed configuration instructions, see [CONFIGURATION.md](CONFIGURATION.md)

#### Generating RSA Keys

The project includes a key generator utility to create new RSA-2048 key pairs:

```bash
# Generate new RSA keys
cargo run -p keygen --release

# The tool will output:
# - Proxy server public and private keys
# - Agent user public and private keys
# Copy these keys to your configuration files
```

See [keygen/README.md](keygen/README.md) for detailed instructions.

#### Quick Start - Agent Configuration

Edit `agent.toml`:

```toml
http_listen_addr = "127.0.0.1:8080"
socks5_listen_addr = "127.0.0.1:1080"
proxy_addr = "your-proxy-server.com:8443"
proxy_rsa_public_key = "..."  # Copy from proxy after first run

[user]
username = "your-username"
password = "your-password"

[connection_pool]
max_size = 10
idle_timeout_secs = 300
```

#### Quick Start - Proxy Configuration

Edit `proxy.toml`:

```toml
listen_addr = "0.0.0.0:8443"
api_listen_addr = "127.0.0.1:8444"
max_connections_per_user = 100

[users.user1]
username = "user1"
password = "secure-password"
bandwidth_limit = 10485760  # 10 MB/s
```

### Running

#### Start Proxy Server

```bash
./target/release/proxy --config proxy.toml
```

Or with environment variables:
```bash
PROXY_LISTEN_ADDR=0.0.0.0:8443 ./target/release/proxy
```

#### Start Agent

```bash
./target/release/agent --config agent.toml
```

Or with environment variables:
```bash
AGENT_HTTP_ADDR=127.0.0.1:8080 \
AGENT_SOCKS5_ADDR=127.0.0.1:1080 \
AGENT_PROXY_ADDR=proxy.example.com:8443 \
./target/release/agent
```

### Using the Proxy

The agent automatically detects whether you're using HTTP or SOCKS5 protocol - just connect to port 8080.

#### HTTP Proxy

Configure your application to use HTTP proxy at `127.0.0.1:8080`:

```bash
# Using curl
curl -x http://127.0.0.1:8080 https://example.com

# Using environment variable
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

#### SOCKS5 Proxy

Connect to the same address - the agent auto-detects SOCKS5:

```bash
# Using curl - same port, auto-detected as SOCKS5
curl --socks5 127.0.0.1:8080 https://example.com
```

## API Reference

The proxy server exposes a REST API on the configured `api_listen_addr` (default: 127.0.0.1:8444).

### Health Check
```bash
GET /health
```

### Configuration Management
```bash
# Get current configuration
GET /config

# Update configuration
PUT /config
Content-Type: application/json
{
  "max_connections_per_user": 150,
  "session_timeout_secs": 7200
}
```

### User Management
```bash
# List all users
GET /users

# Add a new user
POST /users
Content-Type: application/json
{
  "username": "newuser",
  "password": "secure-password",
  "bandwidth_limit": 5242880
}

# Remove a user
DELETE /users/{username}

# Update user bandwidth limit
PUT /users/{username}/bandwidth
Content-Type: application/json
{
  "bandwidth_limit": 10485760
}

# Get user statistics
GET /users/{username}/stats
```

### Connection Monitoring
```bash
# List active connections
GET /connections

# Get overall statistics
GET /stats
```

### Example API Calls

```bash
# Add a new user
curl -X POST http://127.0.0.1:8444/users \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret123", "bandwidth_limit": 10485760}'

# Get user statistics
curl http://127.0.0.1:8444/users/alice/stats

# List active connections
curl http://127.0.0.1:8444/connections

# Check overall stats
curl http://127.0.0.1:8444/stats
```

## Security Features

### Encryption
- **RSA-2048**: For secure AES key exchange
- **AES-256-GCM**: For encrypting all traffic data
- **Per-User Keys**: Each user has unique RSA key pair

### Authentication
- Username/password authentication
- Password hashing with SHA-256
- Session-based authentication after initial handshake

### Isolation
- Per-user bandwidth limits
- Connection limits per user
- Session isolation between users

## Monitoring

### Tokio Console

Enable tokio-console for real-time async task monitoring:

```bash
# Terminal 1: Start with tokio-console enabled
RUSTFLAGS="--cfg tokio_unstable" cargo run -p proxy

# Terminal 2: Connect with tokio-console
tokio-console
```

### Logging

Set log level with `RUST_LOG` environment variable:

```bash
RUST_LOG=debug ./target/release/agent
RUST_LOG=info,proxy=debug ./target/release/proxy
```

## Development

### Project Structure

```
ppaass-ai/
├── common/          # Shared library
│   └── src/
│       ├── bandwidth.rs    # Bandwidth limiting
│       ├── config.rs       # Configuration structs
│       ├── crypto.rs       # Cryptography
│       ├── error.rs        # Error types
│       ├── protocol.rs     # Protocol definitions
│       └── lib.rs
├── agent/           # Client-side agent
│   └── src/
│       ├── config.rs           # Agent configuration
│       ├── connection_pool.rs  # Connection pooling
│       ├── http_proxy.rs       # HTTP proxy handler
│       ├── socks5_proxy.rs     # SOCKS5 proxy handler
│       └── main.rs
├── proxy/           # Server-side proxy
│   └── src/
│       ├── api.rs              # REST API
│       ├── config.rs           # Proxy configuration
│       ├── relay.rs            # Traffic relay
│       ├── session.rs          # Session management
│       ├── user_manager.rs     # User management
│       └── main.rs
└── doc/
    └── requirements.md
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for specific component
cargo test -p common
cargo test -p agent
cargo test -p proxy
```

## Performance Considerations

- Connection pooling reduces handshake overhead
- Efficient buffer management with `bytes` crate
- Async I/O with `tokio` for high concurrency
- Token bucket algorithm for smooth bandwidth limiting

## Troubleshooting

### RSA Key Generation
Keys are automatically generated on first run. To regenerate:
1. Delete the keys from config file
2. Restart the application

### Connection Issues
- Verify firewall rules allow traffic on configured ports
- Check that proxy address is reachable from agent
- Verify RSA public key matches between agent and proxy

### Performance Issues
- Increase connection pool size in agent config
- Adjust bandwidth limits if throttling is too aggressive
- Monitor with tokio-console to identify bottlenecks

## License

MIT

## Contributing

Contributions are welcome! Please ensure:
- Code follows Rust best practices
- All tests pass
- New features include appropriate tests
- Documentation is updated

