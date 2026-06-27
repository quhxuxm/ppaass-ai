package com.ppaass.ai.agent;

final class QuicPolicyOption {
    final String value;
    final String label;

    QuicPolicyOption(String value, String label) {
        this.value = value;
        this.label = label;
    }

    @Override
    public String toString() {
        return label;
    }
}
