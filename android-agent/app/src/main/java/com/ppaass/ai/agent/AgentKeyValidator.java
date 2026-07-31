package com.ppaass.ai.agent;

final class AgentKeyValidator {
    private AgentKeyValidator() {
    }

    static void validateMatchingKeyPair(String privateKeyPem, String publicKeyPem)
            throws AgentAuthClient.AuthException {
        final boolean matches;
        try {
            matches = NativeAgent.validateKeyPair(privateKeyPem, publicKeyPem);
        } catch (RuntimeException | UnsatisfiedLinkError error) {
            throw new AgentAuthClient.AuthException(
                    "无法校验 Proxy Registry 返回的私钥",
                    error);
        }
        if (!matches) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Registry 返回的公钥和私钥不匹配");
        }
    }

}
