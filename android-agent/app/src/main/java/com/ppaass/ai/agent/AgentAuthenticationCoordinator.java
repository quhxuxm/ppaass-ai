package com.ppaass.ai.agent;

import java.io.IOException;

final class AgentAuthenticationCoordinator {
    private static long generation;
    private static long activeAttempt;

    private AgentAuthenticationCoordinator() {
    }

    static synchronized long begin() {
        activeAttempt = ++generation;
        return activeAttempt;
    }

    static synchronized boolean cancel(long attempt) {
        if (attempt == 0 || activeAttempt != attempt) {
            return false;
        }
        activeAttempt = 0;
        return true;
    }

    static synchronized void cancelAll() {
        activeAttempt = 0;
        generation++;
    }

    static synchronized boolean isLatest(long attempt) {
        return attempt != 0 && generation == attempt;
    }

    static synchronized boolean commitIfCurrent(long attempt, CommitAction action)
            throws IOException {
        if (attempt == 0 || activeAttempt != attempt) {
            return false;
        }
        try {
            action.run();
            return true;
        } finally {
            if (activeAttempt == attempt) {
                activeAttempt = 0;
            }
        }
    }

    interface CommitAction {
        void run() throws IOException;
    }
}
