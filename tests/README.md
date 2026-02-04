# PPAASS Integration and Performance Tests

This directory contains integration and performance testing tools for the PPAASS proxy system.

## Features

- **Mock Target Servers**: HTTP server and TCP echo server for testing
- **Mock Clients**: HTTP and SOCKS5 clients for testing proxy functionality
- **Integration Tests**: Test authentication, connection, and data forwarding
- **Performance Tests**: Load testing with configurable concurrency and duration
- **Performance Reports**: Generate HTML, JSON, and Markdown reports with charts

## Quick Start

### 1. Start Mock Target Servers

In one terminal:

```bash
./run-tests.sh mock-target
```

This starts:
- HTTP server on port 9090 (endpoints: /health, /echo, /large, /json)
- TCP echo server on port 9091

### 2. Start Agent and Proxy

In separate terminals:

```bash
# Start proxy
cd /path/to/ppaass-ai
cargo run --release -p proxy -- --config config/proxy.toml

# Start agent
cargo run --release -p agent -- --config config/agent.toml
```

### 3. Run Integration Tests

```bash
./run-tests.sh integration
```

### 4. Run Performance Tests

```bash
# Run with default settings (100 concurrent connections, 60 seconds)
./run-tests.sh performance

# Run with custom settings (200 concurrent, 120 seconds)
./run-tests.sh performance 200 120
```

### 5. Run All Tests

```bash
./run-tests.sh all
```

## Manual Usage

You can also run the test binary directly:

```bash
# Build
cargo build --release -p integration-tests

# Start mock target servers
cargo run --release -p integration-tests -- mock-target

# Run integration tests
cargo run --release -p integration-tests -- integration
    --agent-addr 127.0.0.1:7070
    --proxy-addr 127.0.0.1:8080

# Run performance tests
cargo run --release -p integration-tests -- performance 
    --agent-addr 127.0.0.1:7070
    --proxy-addr 127.0.0.1:8080
    --concurrency 100
    --duration 60
    --output performance-report.html
```

## Integration Tests

The integration test suite includes:

1. **HTTP Health Check**: Test basic HTTP GET request
2. **HTTP Echo**: Test HTTP POST with request/response body validation
3. **HTTP Large Response**: Test handling of large responses (1MB+)
4. **HTTP JSON**: Test JSON response parsing
5. **SOCKS5 Echo**: Test basic SOCKS5 connection and echo
6. **SOCKS5 Large Data**: Test large data transfer through SOCKS5
7. **SOCKS5 UDP Associate**: Test UDP forwarding via SOCKS5 UDP ASSOCIATE (UDP echo)

### Testing SOCKS5 UDP Associate

The integration test suite now includes a test for SOCKS5 UDP Associate, which verifies UDP forwarding through the agent and proxy. This test sends a UDP packet through the SOCKS5 proxy to the mock UDP echo server and checks that the response matches the request.

**How to run:**

- The UDP echo server is started automatically with the mock target servers (on port 9092 by default).
- Run the integration tests as usual:

```bash
./run-tests.sh integration
```

or manually:

```bash
cargo run --release -p integration-tests -- integration --agent-addr 127.0.0.1:7070 --proxy-addr 127.0.0.1:8080
```

- The test result for "SOCKS5 UDP Associate" will be shown in the output summary.

**What it does:**
- Performs a SOCKS5 UDP ASSOCIATE handshake
- Sends a UDP packet to the mock UDP echo server (port 9092)
- Verifies the echoed response matches the sent data

## Performance Tests

Performance tests measure:

### Request Metrics
- Total requests
- Success rate
- Requests per second
- Throughput (Mbps)

### Latency Metrics (HTTP and SOCKS5)
- Average latency
- Min/Max latency
- P50, P95, P99 percentiles

### System Metrics
- CPU usage
- Memory usage
- Peak memory

## Performance Reports

Three report formats are generated:

### 1. HTML Report (`performance-report.html`)
Interactive report with:
- Summary metrics cards
- Request distribution charts
- Latency distribution charts
- Detailed metric tables

### 2. JSON Report (`performance-report.json`)
Machine-readable format with all metrics for further analysis.

### 3. Markdown Report (`performance-report.md`)
Human-readable text format suitable for documentation.

## Architecture

### Mock Target Servers

**HTTP Server** (`src/mock_target.rs`):
- `/health` - Returns "OK"
- `/echo` - Echoes back request body
- `/large` - Returns 1MB response
- `/json` - Returns JSON response

**TCP Echo Server** (`src/mock_target.rs`):
- Echoes back all received data
- Used for SOCKS5 testing

### Mock Clients

**HTTP Client** (`src/mock_client.rs`):
- Supports GET and POST requests
- Connects through agent proxy
- Measures response time

**SOCKS5 Client** (`src/mock_client.rs`):
- Performs SOCKS5 handshake
- Connects to target through agent
- Sends/receives data with timing

### Test Modules

- `src/integration_tests.rs` - Integration test suite
- `src/performance_tests.rs` - Performance test implementation
- `src/report.rs` - Report generation (HTML, JSON, Markdown)

## Configuration

### Environment Variables

- `AGENT_ADDR` - Agent server address (default: `127.0.0.1:7070`)
- `PROXY_ADDR` - Proxy server address (default: `127.0.0.1:8080`)
- `RUST_LOG` - Log level (e.g., `info`, `debug`, `trace`)

### Custom Configuration

Edit addresses and ports in the script or use environment variables:

```bash
AGENT_ADDR=10.0.0.1:7070 PROXY_ADDR=10.0.0.2:8080 ./run-tests.sh integration
```

## Troubleshooting

### "Connection refused" errors

Make sure:
1. Mock target servers are running (`./run-tests.sh mock-target`)
2. Agent server is running
3. Proxy server is running
4. Correct addresses are configured

### Performance test failures

- Increase duration for more stable results
- Reduce concurrency if resource-limited
- Check system resources (CPU, memory, network)

### Build errors

```bash
# Clean and rebuild
cargo clean
cargo build --workspace --release
```

## Development

### Running Unit Tests

```bash
cargo test -p integration-tests
```

### Adding New Tests

1. Add test function to `src/integration_tests.rs`
2. Call from `run_all_tests()`
3. Update this README

### Modifying Mock Servers

Edit `src/mock_target.rs` to add new endpoints or modify behavior.

## License

Same as main PPAASS project (MIT).
