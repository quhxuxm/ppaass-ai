package com.ppaass.ai.agent;

final class AgentDeviceAuthModels {
    private AgentDeviceAuthModels() {
    }

    static final class Authorization {
        final String deviceCode;
        final String verificationUrl;
        final int expiresInSeconds;
        final int intervalSeconds;

        Authorization(
                String deviceCode,
                String verificationUrl,
                int expiresInSeconds,
                int intervalSeconds) {
            this.deviceCode = deviceCode;
            this.verificationUrl = verificationUrl;
            this.expiresInSeconds = expiresInSeconds;
            this.intervalSeconds = intervalSeconds;
        }
    }

    static final class PollResult {
        enum Status { AUTHORIZED, PENDING, SLOW_DOWN }

        final Status status;
        final int nextPollDelaySeconds;
        final AgentAuthClient.LoginResult loginResult;

        private PollResult(
                Status status,
                int nextPollDelaySeconds,
                AgentAuthClient.LoginResult loginResult) {
            this.status = status;
            this.nextPollDelaySeconds = nextPollDelaySeconds;
            this.loginResult = loginResult;
        }

        static PollResult authorized(AgentAuthClient.LoginResult result) {
            return new PollResult(Status.AUTHORIZED, 0, result);
        }

        static PollResult pending(int delay) {
            return new PollResult(Status.PENDING, delay, null);
        }

        static PollResult slowDown(int delay) {
            return new PollResult(Status.SLOW_DOWN, delay, null);
        }
    }
}
