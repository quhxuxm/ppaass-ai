# PPAASS HTTP Range Large Download Test Report

- **Duration:** 1 seconds
- **Agent:** 127.0.0.1:11080
- **URL:** CONNECT 127.0.0.1:9090/large?size=134217728
- **File Size:** 134217728 bytes
- **Chunk Size:** 1048576 bytes
- **Concurrency:** 32
- **Rounds:** 2
- **Total Chunks:** 256
- **Successful Chunks:** 256
- **Failed Chunks:** 0
- **Success Rate:** 100.00%
- **Chunks/sec:** 213.98
- **Throughput:** 1795.00 Mbps

## Chunk Latency Metrics

| Metric | Value |
|--------|-------|
| Average Latency | 142.968 ms |
| Min Latency | 59.072 ms |
| P50 Latency | 134.911 ms |
| P95 Latency | 206.847 ms |
| P99 Latency | 261.119 ms |
| Max Latency | 268.031 ms |
| Total Bytes Downloaded | 268435456 |

## System Metrics

- **CPU Usage:** 82.27%
- **Memory Usage:** 12366 MB
- **Peak Memory:** 12360 MB
