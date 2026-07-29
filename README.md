# PPAASS - Secure Proxy Application

A high-performance, secure proxy application built with Rust, featuring HTTP and SOCKS5 protocol support with end-to-end
encryption.

## Features

- **Dual Protocol Support**: Automatically detects and handles both HTTP and SOCKS5 protocols
- **End-to-End Encryption**: RSA for key exchange, AES-256-GCM for data encryption
- **Multi-User Support**: Each user has their own RSA key pair
- **User Management Console**: Axum API and Vue/PrimeVue UI backed by the same user repository as Proxy authentication
- **Selectable UDP Transport**: TCP targets always use the original independent framed TCP path. Proxied UDP can use native encrypted UDP (`udp`), TCP/Yamux (`tcp`), or per-session automatic fallback from encrypted UDP to TCP/Yamux after a control timeout (`auto`).
- **Authenticated Native UDP**: Each native UDP session uses RSA identity authentication and session establishment, HKDF-separated send/receive keys, and independently authenticated AES-256-GCM datagrams with replay protection and bounded fragmentation
- **Secure DNS Resolution**: DNS resolution performed on proxy side
- **Production Ready**: Built with tokio and graceful shutdown

## Architecture

The application consists of six main components:

1. **Agent**: Runs on client machine, forwards traffic to proxy
2. **Proxy**: Server-side component that connects to target servers
3. **Proxy Web**: Axum API and Vue/PrimeVue user management console
4. **Proxy User Store**: Database-independent user CRUD contract with a SQLite adapter
5. **Protocol**: Shared protocol definition and crypto implementation
6. **Common**: Shared utilities and error types

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
cargo build --release -p proxy-web

# Build the Vue + PrimeVue console
cd proxy-web/frontend
npm install
npm run build
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

3. Start Proxy Web, register a user, and approve the user's key request. Proxy Web is the only
   writer for the shared SQLite user database.

4. Sign in from the Agent UI. It obtains the approved managed credential from Proxy Web.

5. Start the agent:

```bash
cargo run --release -p desktop-agent-be --bin desktop-agent -- --config config/agent.toml
```

6. Configure your applications to use the proxy at `127.0.0.1:1080`

### Desktop Agent Login

The Tauri desktop app requires a Proxy Web login once per application process before it
loads the Agent workspace. Its authentication endpoint is read only by the Rust backend
from the top-level `proxy_web_url` field in the active `agent.toml`; it is not returned
to or editable by the Vue webview. Loopback endpoints may use HTTP, while remote
endpoints must use HTTPS.

After authentication, the Rust backend—not the Vue webview—checks the approved key
state and expiry, downloads the user's private key, verifies it against the public key,
stores it under the per-user application data directory, and updates
`username`/`private_key_path` in the active `agent.toml`. On Unix, the credential
directory is mode `0700` and the private-key file is mode `0600`. Passwords, session
cookies, CSRF tokens, and PEM contents are never returned to Vue or written to tracing
logs. Logging out stops the Agent before clearing the in-memory desktop login state.

```bash
cd desktop-agent-ui
npm install
npm run tauri dev
```

### Desktop TUN Helper Mode

macOS TUN mode can run the existing `desktop-agent` binary in a privileged helper mode so the normal agent does not need to ask for sudo on every start. `start-agent.sh` and `start-agent.command` install the already-built `desktop-agent` automatically when `[tun] enabled = true` and `macos_helper_enabled = true`, then expose `/var/run/ppaass-ai/tun-helper.sock` to the current UID. No separate helper binary is built. On Windows, `start-agent.bat` creates a highest-privilege scheduled task the first time TUN mode is started, then uses that task for later starts.

## Configuration

### Agent Configuration (`config/agent.toml`)

```toml
listen_addr = "127.0.0.1:1080"      # Local proxy address
proxy_addrs = ["proxy.example.com:8080"] # Remote proxy addresses
username = "local-test"                    # Legacy CLI compatibility username
private_key_path = "keys/local-test.pem"  # Local-only private key; never commit it
transport_mode = "udp"               # auto: each UDP session falls back to TCP/Yamux on timeout; udp: native encrypted UDP (default); tcp: TCP/Yamux
udp_session_pool_size = 4             # 1-8; stateful native UDP sessions used only by proxied UDP
connect_timeout_secs = 30             # Connection timeout
compression_mode = "none"             # Framed TCP/TCP-Yamux only; native UDP datagrams are not compressed

[yamux.udp]
sessions = 5                         # Max UDP relay raw Yamux outer sessions, grown on demand
max_streams_per_session = 128        # UDP relay substreams per session

[tun]
proxy_udp = true                     # false: send ordinary UDP directly; proxy DNS and application-layer QUIC policy stay independent
proxy_dns = false                    # DNS proxying remains independently configurable
quic_policy = "allow"               # application UDP/443 policy: allow direct/proxied QUIC; block forces application TCP/TLS fallback

[tun.packet_capture]
file = "captures/ppaass-tun.pcap"   # DLT_RAW PCAP; created when runtime capture is enabled
```

Desktop packet capture is runtime-controlled and defaults to off; toggling or clearing it does not restart the agent. It covers TUN traffic plus local HTTP and SOCKS5 proxy connections, including SOCKS5 UDP, in both directions over IPv4 and IPv6. The output opens directly in Wireshark. TUN packets are recorded at the PPAASS tunnel boundary; explicit proxy streams are represented as valid raw IP packets between the real client and agent listener endpoints. Application-level encryption such as TLS remains encrypted.
PCAP writes run on a dedicated buffered writer thread. The packet path uses a bounded non-blocking queue; if storage cannot keep up, capture copies are dropped instead of slowing proxy traffic.
The desktop app's dedicated **Packet Capture** page shows direction, protocol, endpoints, byte counts, packet summaries, filters, and a short payload preview while retaining the PCAP as the source of truth.

Android also provides runtime packet capture for VPN/TUN and explicit HTTP/SOCKS5 TCP ingress, with persistent proxy-protocol labels, safe PCAP append, and an adaptive full-height packet list. Its local SOCKS5 server intentionally does not support UDP ASSOCIATE, so SOCKS5 UDP capture remains a desktop-only capability. Android DNS records can be filtered and selected to add or remove matching direct-access rules; see [android-agent/README.md](android-agent/README.md).

The old `transport_mode = "quic"` and `quic_connection_pool_size` settings are intentionally incompatible and are rejected. Update them explicitly to `transport_mode = "udp"` and `udp_session_pool_size`.

### Proxy Configuration (`config/proxy.toml`)

```toml
listen_addr = "0.0.0.0:8080"              # Proxy listen address
users_database_path = "data/proxy-users.sqlite3" # Required user database; Proxy opens it read-only
access_log_database_path = "data/proxy-access.sqlite3" # Required, separate writable access database
transport_identity_private_key_path = "data/proxy-identity-private.pem" # Required PKCS#8 identity
udp_relay_max_flows = 256                  # Inner target sockets per shared UDP relay
udp_session_limit = 4096                   # Authenticated native UDP sessions
udp_session_limit_per_username = 64        # Per-user sessions for multiple devices/restarts
udp_session_channel_size = 256             # Datagrams queued per native UDP session
udp_session_max_flows = 256                # Outer flows per native UDP session
```

Proxy requires the SQLite user database and has no file-based user fallback. Proxy Web owns schema
migrations and user writes; Proxy opens the same user database read-only and writes visit history
only to the physically separate access database. New user changes are visible to subsequent TCP
and UDP authentications without restarting Proxy.

See [`proxy-web/README.md`](proxy-web/README.md) for local development, administrator authentication, CRUD endpoints, and the Vue console.

The proxy listens on both TCP and raw UDP at the same numeric `listen_addr` port. Allow that port for both protocols in the server firewall when native UDP transport is used.
Existing flow IDs remain idempotent at capacity, while new flows are rejected before a target socket or worker is created. Fragment reassembly is also bounded independently per authenticated session (64 incomplete messages and 1 MiB by default).

## Security

- **RSA-2048**: Authenticates the user identity and establishes native UDP session material
- **HKDF Key Separation**: Derives independent Agent-to-Proxy and Proxy-to-Agent keys and nonce prefixes
- **AES-256-GCM**: Protects every native UDP datagram independently; version, session ID, sequence number, and other header fields are authenticated as AAD
- **Replay and Fragment Protection**: Per-direction packet sequences and a sliding replay window reject duplicate or stale packets while permitting bounded reordering; oversized payloads use bounded fragments that are each authenticated independently
- **Stable TCP Security Path**: TCP targets retain the original framed PPAASS Auth/Connect/Data encryption; TCP-mode UDP retains the existing TCP/Yamux business-stream protocol
- **Timestamp Validation**: Prevents replay attacks (5-minute tolerance)
- **Secure Key Storage**: Private keys stored securely on disk
- **Per-User Authentication**: Each user has unique credentials

## Performance

- **Async I/O**: Built on tokio for high concurrency
- **Native UDP Session Pool**: In UDP mode, proxied UDP flows are mapped stably across 1–8 stateful UDP sessions; the outer transport adds no reliable ordering or retransmission
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
RUST_LOG=proxy_web=debug,proxy_user_store=debug cargo run -p proxy-web
```

## Development

### Project Structure

```
ppaass-ai/
├── desktop-agent-be/  # Client-side desktop agent backend
├── desktop-agent-ui/       # Desktop agent UI
├── proxy/          # Server-side proxy
├── proxy-user-store/ # Database-independent user repository + SQLite adapter
├── proxy-web/      # Axum API and Vue/PrimeVue user management console
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

1. Increase `udp_session_pool_size` for native UDP mode, or adjust UDP Yamux sessions for TCP mode
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
