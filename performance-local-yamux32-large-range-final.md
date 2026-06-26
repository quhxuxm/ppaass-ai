# PPAASS HTTP Range Large Download Test Report

- **Duration:** 1 seconds
- **Agent:** 127.0.0.1:11080
- **URL:** http://127.0.0.1:9090/large?size=134217728
- **File Size:** 134217728 bytes
- **Chunk Size:** 1048576 bytes
- **Concurrency:** 32
- **Rounds:** 2
- **Total Chunks:** 256
- **Successful Chunks:** 256
- **Failed Chunks:** 0
- **Success Rate:** 100.00%
- **Chunks/sec:** 252.33
- **Throughput:** 2116.69 Mbps

## Chunk Latency Metrics

| Metric | Value |
|--------|-------|
| Average Latency | 119.904 ms |
| Min Latency | 49.344 ms |
| P50 Latency | 118.463 ms |
| P95 Latency | 178.175 ms |
| P99 Latency | 238.335 ms |
| Max Latency | 244.351 ms |
| Total Bytes Downloaded | 268435456 |

## System Metrics

- **CPU Usage:** 84.03%
- **Memory Usage:** 13084 MB
- **Peak Memory:** 13007 MB
