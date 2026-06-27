package com.ppaass.ai.agent;

// 连通性测试结果只作为 UI 渲染输入，避免各测试方法返回松散的字符串数组。
final class ConnectivityCheckResult {
    final String target;
    final String protocol;
    final boolean success;
    final String detail;
    final long durationMs;
    final long rxDelta;
    final long txDelta;

    ConnectivityCheckResult(
            String target,
            String protocol,
            boolean success,
            String detail,
            long durationMs,
            long rxDelta,
            long txDelta) {
        this.target = target;
        this.protocol = protocol;
        this.success = success;
        this.detail = detail;
        this.durationMs = durationMs;
        this.rxDelta = rxDelta;
        this.txDelta = txDelta;
    }
}
