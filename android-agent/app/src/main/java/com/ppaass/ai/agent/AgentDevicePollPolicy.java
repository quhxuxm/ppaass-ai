package com.ppaass.ai.agent;

final class AgentDevicePollPolicy {
    private static final int MAX_DELAY_SECONDS = 5 * 60;

    private AgentDevicePollPolicy() {
    }

    static int delaySeconds(
            int currentIntervalSeconds,
            int retryAfterSeconds,
            boolean slowDown) {
        int current = Math.max(
                1,
                Math.min(currentIntervalSeconds, MAX_DELAY_SECONDS));
        int required = slowDown
                ? Math.min(current + 5, MAX_DELAY_SECONDS)
                : current;
        if (retryAfterSeconds > 0) {
            required = Math.max(
                    required,
                    Math.min(retryAfterSeconds, MAX_DELAY_SECONDS));
        }
        return required;
    }

    static int rateLimitDelaySeconds(
            int status,
            String code,
            int currentIntervalSeconds,
            int retryAfterSeconds) {
        if (status != 429) {
            return 0;
        }
        if ("slow_down".equals(code)) {
            return delaySeconds(currentIntervalSeconds, retryAfterSeconds, true);
        }
        if ("rate_limited".equals(code)) {
            return delaySeconds(currentIntervalSeconds, retryAfterSeconds, false);
        }
        return 0;
    }
}
