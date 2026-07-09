# PPAASS UDP Relay Performance Test Report

**Test Duration:** 20 seconds

## Summary

- **Agent:** 127.0.0.1:11080
- **Target:** 127.0.0.1:9092
- **Concurrency:** 100
- **Payload Size:** 1200 bytes
- **Total Datagrams:** 868672
- **Successful Datagrams:** 868434
- **Failed Datagrams:** 238
- **Failure Rate:** 0.03%
- **Datagrams/sec:** 43036.21
- **Throughput:** 826.07 Mbps

## UDP RTT Metrics

| Metric | Value |
|--------|-------|
| Avg RTT | 1.518 ms |
| Min RTT | 0.196 ms |
| Max RTT | 57.983 ms |
| P50 RTT | 1.462 ms |
| P95 RTT | 2.283 ms |
| P99 RTT | 2.721 ms |

## System Metrics

- **CPU Usage:** 92.84%
- **Memory Usage:** 13127 MB
- **Peak Memory:** 13223 MB
