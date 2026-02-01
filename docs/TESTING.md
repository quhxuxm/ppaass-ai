# Testing Examples and Usage Guide

## Overview

This document provides examples of using the PPAASS integration and performance testing tools.

## Setup

Before running tests, you need to have three components running:

1. Mock target servers (HTTP + TCP echo)
2. Proxy server
3. Agent server

### Terminal Setup

We recommend using 4 terminals:

```
Terminal 1: Mock Target Servers
Terminal 2: Proxy Server
Terminal 3: Agent Server
Terminal 4: Test Runner
```

## Example: Complete Test Run

### Terminal 1: Start Mock Target Servers

```bash
cd /path/to/ppaass-ai
./run-tests.sh mock-target
```

**Expected Output:**
```
[2024-01-31T02:00:00Z INFO  integration_tests::mock_target] Mock HTTP server listening on 127.0.0.1:9090
[2024-01-31T02:00:00Z INFO  integration_tests::mock_target] Mock TCP echo server listening on 127.0.0.1:9091
```

The mock servers provide:
- **HTTP Server (port 9090)**:
  - `GET /health` - Returns "OK"
  - `POST /echo` - Echoes request body
  - `GET /large` - Returns 1MB response
  - `GET /json` - Returns JSON response
- **TCP Echo Server (port 9091)** - Echoes all received data

### Terminal 2: Start Proxy Server

```bash
cd /path/to/ppaass-ai
cargo run --release -p proxy -- --config config/proxy.toml
```

**Expected Output:**
```
[2024-01-31T02:00:00Z INFO  proxy] Starting proxy server
[2024-01-31T02:00:00Z INFO  proxy::server] Proxy server listening on 0.0.0.0:8080
[2024-01-31T02:00:00Z INFO  proxy::api] API server listening on 0.0.0.0:8081
```

### Terminal 3: Start Agent Server

```bash
cd /path/to/ppaass-ai
cargo run --release -p agent -- --config config/agent.toml
```

**Expected Output:**
```
[2024-01-31T02:00:00Z INFO  agent] Starting agent server
[2024-01-31T02:00:00Z INFO  agent::server] Agent server listening on 127.0.0.1:7070
[2024-01-31T02:00:00Z INFO  agent::connection_pool] Connection pool initialized with 10 connections
```

### Terminal 4: Run Integration Tests

```bash
cd /path/to/ppaass-ai
./run-tests.sh integration
```

**Expected Output:**
```
=== Starting Integration Tests ===
[2024-01-31T02:00:01Z INFO  integration_tests::integration_tests] ✓ HTTP Health Check - PASSED (45 ms)
[2024-01-31T02:00:01Z INFO  integration_tests::integration_tests] ✓ HTTP Echo - PASSED (52 ms)
[2024-01-31T02:00:02Z INFO  integration_tests::integration_tests] ✓ HTTP Large Response - PASSED (234 ms)
[2024-01-31T02:00:02Z INFO  integration_tests::integration_tests] ✓ HTTP JSON Response - PASSED (48 ms)
[2024-01-31T02:00:02Z INFO  integration_tests::integration_tests] ✓ SOCKS5 TCP Echo - PASSED (61 ms)
[2024-01-31T02:00:03Z INFO  integration_tests::integration_tests] ✓ SOCKS5 Large Data Transfer - PASSED (89 ms)
=== Integration Tests Complete ===
Total: 6, Passed: 6, Failed: 0
```

### Terminal 4: Run Performance Tests

```bash
cd /path/to/ppaass-ai
./run-tests.sh performance 100 60
```

**Expected Output:**
```
=== Starting Performance Tests ===
Agent: 127.0.0.1:7070, Concurrency: 100, Duration: 60s
[Running tests for 60 seconds...]
=== Performance Tests Complete ===
Total Requests: 12543
Success Rate: 99.87%
Requests/sec: 209.05
Throughput: 156.42 Mbps
✓ Performance test complete
Reports generated:
  - performance-report-20240131-020530.html
  - performance-report-20240131-020530.json
  - performance-report-20240131-020530.md
```

## Performance Report Example

The HTML report includes:

### Summary Metrics
- **Total Requests**: 12,543
- **Success Rate**: 99.87%
- **Requests/sec**: 209.05
- **Throughput**: 156.42 Mbps

### HTTP Metrics
| Metric | Value |
|--------|-------|
| Total Requests | 7,526 |
| Successful | 7,518 |
| Failed | 8 |
| Avg Latency | 47.52 ms |
| P50 Latency | 44.00 ms |
| P95 Latency | 78.00 ms |
| P99 Latency | 112.00 ms |

### SOCKS5 Metrics
| Metric | Value |
|--------|-------|
| Total Requests | 5,017 |
| Successful | 5,009 |
| Failed | 8 |
| Avg Latency | 38.21 ms |
| P50 Latency | 36.00 ms |
| P95 Latency | 62.00 ms |
| P99 Latency | 89.00 ms |

### System Metrics
- **CPU Usage**: 65.3%
- **Memory Usage**: 456 MB
- **Peak Memory**: 512 MB

## Running Tests with Custom Configuration

### Custom Agent/Proxy Addresses

```bash
# For remote testing
AGENT_ADDR=10.0.0.1:7070 PROXY_ADDR=10.0.0.2:8080 ./run-tests.sh integration

# For custom ports
AGENT_ADDR=127.0.0.1:9000 ./run-tests.sh performance 200 120
```

### Custom Concurrency and Duration

```bash
# Light load test: 50 concurrent connections, 30 seconds
./run-tests.sh performance 50 30

# Medium load test: 100 concurrent connections, 60 seconds
./run-tests.sh performance 100 60

# Heavy load test: 500 concurrent connections, 300 seconds
./run-tests.sh performance 500 300
```

### Run All Tests

```bash
# Run integration tests followed by performance tests
./run-tests.sh all 100 60
```

## Direct Binary Usage

You can also use the compiled binary directly:

```bash
# Build
cargo build --release -p integration-tests

# Use the binary
./target/release/integration-tests mock-target
./target/release/integration-tests integration --agent-addr 127.0.0.1:7070
./target/release/integration-tests performance \
    --agent-addr 127.0.0.1:7070 \
    --concurrency 100 \
    --duration 60 \
    --output my-report.html
```

## Troubleshooting Common Issues

### Issue: "Connection refused"

**Solution:** Make sure all three components are running:
1. Check mock target servers: `curl http://127.0.0.1:9090/health`
2. Check proxy health: `curl http://127.0.0.1:8081/health`
3. Check agent is listening: `netstat -an | grep 7070`

### Issue: "Authentication failed"

**Solution:** Verify agent configuration:
1. Check username in `config/agent.toml`
2. Verify private key path is correct
3. Ensure user exists on proxy side

### Issue: High failure rate in performance tests

**Possible causes:**
- System resource limits (increase with `ulimit -n 10000`)
- Network bandwidth limits
- Too much concurrency for available resources

**Solution:** Start with lower concurrency (e.g., 50) and increase gradually.

### Issue: Tests running too slow

**Solution:**
- Reduce test duration
- Check system resources (CPU, memory, disk I/O)
- Ensure tests are built in release mode

## Interpreting Results

### Good Performance Indicators
- Success rate > 99%
- P95 latency < 100ms for local testing
- Throughput matching network capacity
- Stable memory usage

### Warning Signs
- Success rate < 95%
- P99 latency > 1000ms
- Increasing memory usage
- High CPU usage (> 80%)

### Baseline Expectations

For local testing (all components on same machine):
- **Latency**: P50 < 50ms, P95 < 100ms, P99 < 200ms
- **Throughput**: 100+ Mbps
- **Success Rate**: > 99.5%
- **Requests/sec**: 200+ (depends on hardware)

For network testing (components on different machines):
- Add network latency to expectations
- Throughput limited by network bandwidth
- Success rate should still be > 99%

## Advanced Usage

### Custom Test Scenarios

You can modify the test sources to create custom scenarios:

1. Edit `tests/src/integration_tests.rs` to add new test cases
2. Edit `tests/src/performance_tests.rs` to adjust load patterns
3. Edit `tests/src/mock_target.rs` to add new endpoints

### Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Build
        run: cargo build --release --workspace
      
      - name: Start mock targets
        run: ./run-tests.sh mock-target &
        
      - name: Start proxy
        run: cargo run --release -p proxy -- --config config/proxy.toml &
        
      - name: Start agent
        run: cargo run --release -p agent -- --config config/agent.toml &
        
      - name: Run integration tests
        run: ./run-tests.sh integration
```

## Next Steps

1. Run integration tests to verify basic functionality
2. Run performance tests with low concurrency (50-100)
3. Analyze reports and identify bottlenecks
4. Gradually increase load to find system limits
5. Use reports to guide optimization efforts

For more information, see:
- `tests/README.md` - Detailed testing documentation
- `README.md` - Main project documentation
- `doc/requirements.md` - System requirements and architecture
