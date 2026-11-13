package com.ppaass.ai.agent;

final class AgentDevicePollPolicy {
    private static final int MAX_DELAY_SECONDS = 5 * 60;

    private AgentDevicePollPolicy() {
    }

    static int delaySeconds(
            int currentIntervalSeconds,
            int retryAfterSeconds) {
        int required = Math.max(
                1,
                Math.min(currentIntervalSeconds, MAX_DELAY_SECONDS));
        if (retryAfterSeconds > 0) {
            required = Math.max(
                    required,
                    Math.min(retryAfterSeconds, MAX_DELAY_SECONDS));
        }
        return required;
    }
}
