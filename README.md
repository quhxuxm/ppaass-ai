# PPAASS - Secure Proxy Application

A high-performance, secure proxy application built with Rust, featuring HTTP and SOCKS5 protocol support with end-to-end
encryption.

## Features

- **Dual Protocol Support**: Automatically detects and handles both HTTP and SOCKS5 protocols
- **End-to-End Encryption**: RSA for key exchange, AES-256-GCM for data encryption
- **Multi-User Support**: Each user has their own RSA key pair
- **Hybrid Transport by Default**: TCP targets always use independent framed TCP connections; UDP relay uses a configurable QUIC connection pool when `transport_mode = "quic"`, with a full-TCP UDP/Yamux option available through `transport_mode = "tcp"`
- **Encrypted PPAASS Frames**: The existing RSA authentication and AES-256-GCM encrypted Auth/Connect/Data frames are unchanged inside both UDP QUIC streams and TCP transports
- **Secure DNS Resolution**: DNS resolution performed on proxy side
- **Production Ready**: Built with tokio and graceful shutdown

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
cargo build --release -p desktop-agent-be
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

3. Add the user's public key to `config/users.toml`

4. Update `config/agent.toml` with your username and private key path

5. Start the agent:

```bash
cargo run --release -p desktop-agent-be --bin desktop-agent -- --config config/agent.toml
```

6. Configure your applications to use the proxy at `127.0.0.1:1080`

### Desktop TUN Helper Mode

macOS TUN mode can run the existing `desktop-agent` binary in a privileged helper mode so the normal agent does not need to ask for sudo on every start. `start-agent.sh` and `start-agent.command` install the already-built `desktop-agent` automatically when `[tun] enabled = true` and `macos_helper_enabled = true`, then expose `/var/run/ppaass-ai/tun-helper.sock` to the current UID. No separate helper binary is built. On Windows, `start-agent.bat` creates a highest-privilege scheduled task the first time TUN mode is started, then uses that task for later starts.

## Configuration

### Agent Configuration (`config/agent.toml`)

```toml
listen_addr = "127.0.0.1:1080"      # Local proxy address
proxy_addrs = ["proxy.example.com:8080"] # Remote proxy addresses
username = "user1"                    # Your username
private_key_path = "keys/user1.pem"  # Path to your RSA private key
transport_mode = "quic"              # quic: TCP over TCP + UDP over QUIC (default); tcp: all traffic over TCP
quic_connection_pool_size = 4         # 1-8; independent QUIC congestion windows for UDP relay only
connection_timeout_secs = 30                # Connection timeout

[yamux.udp]
sessions = 5                         # Max UDP relay raw Yamux outer sessions, grown on demand
max_streams_per_session = 128        # UDP relay substreams per session

[tun]
proxy_udp = true                     # false: send ordinary UDP directly; proxy DNS and QUIC stay independent
proxy_dns = false                    # DNS proxying remains independently configurable
quic_policy = "allow"               # allow: direct QUIC where permitted; UDP-over-QUIC mode forces proxied HTTP/3 to fall back to TCP/TLS
```

### Proxy Configuration (`config/proxy.toml`)

```toml
listen_addr = "0.0.0.0:8080"              # Proxy listen address
users_path = "config/users.toml"          # Users configuration file
```

The proxy listens on both TCP and UDP at `listen_addr`. Allow the configured port for both protocols in the server firewall when QUIC is used.

## Security

- **RSA-2048**: Used for secure key exchange
- **AES-256-GCM**: Used for data encryption with authenticated encryption
- **QUIC/TLS**: Adds transport encryption around unchanged PPAASS encrypted UDP relay frames in hybrid mode; TCP target data remains on the original framed TCP path
- **Timestamp Validation**: Prevents replay attacks (5-minute tolerance)
- **Secure Key Storage**: Private keys stored securely on disk
- **Per-User Authentication**: Each user has unique credentials

## Performance

- **Async I/O**: Built on tokio for high concurrency
- **UDP QUIC Multiplexing**: In hybrid mode, UDP targets use configurable connection pools and independent QUIC bidirectional streams; TCP targets never enter the QUIC pool
- **Stable TCP Path**: HTTP, SOCKS5 TCP, and TUN TCP targets always retain independent framed TCP connections
- **Full-TCP Option**: UDP relay uses raw TCP/Yamux when `transport_mode = "tcp"`, so both TCP and UDP traffic are carried over TCP
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

### Logging

Set log level via environment variable:

```bash
RUST_LOG=info cargo run -p proxy
RUST_LOG=debug cargo run -p desktop-agent-be --bin desktop-agent
```

## Development

### Project Structure

```
ppaass-ai/
├── desktop-agent-be/  # Client-side desktop agent backend
├── desktop-agent-ui/       # Desktop agent UI
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
2. Verify proxy server process is running and listening on the configured proxy port
3. Check logs for authentication errors
4. Ensure private key matches user's public key

### Performance Issues

1. Increase pool size in agent configuration
2. Check Yamux session and stream settings
3. Review network latency

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
- deadpool - Connection pooling
