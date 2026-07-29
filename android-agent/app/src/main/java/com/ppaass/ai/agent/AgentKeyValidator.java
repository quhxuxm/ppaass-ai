package com.ppaass.ai.agent;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

final class AgentKeyValidator {
    private static final int MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES = 64 * 1024;

    private AgentKeyValidator() {
    }

    static void validateMatchingKeyPair(String privateKeyPem, String publicKeyPem)
            throws AgentAuthClient.AuthException {
        final boolean matches;
        try {
            matches = NativeAgent.validateKeyPair(privateKeyPem, publicKeyPem);
        } catch (RuntimeException | UnsatisfiedLinkError error) {
            throw new AgentAuthClient.AuthException(
                    "无法校验 Proxy Web 返回的私钥",
                    error);
        }
        if (!matches) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Web 返回的公钥和私钥不匹配");
        }
    }

    static void validateProxyIdentityPublicKey(String publicKeyPem)
            throws AgentAuthClient.AuthException {
        if (publicKeyPem == null
                || publicKeyPem.isEmpty()
                || publicKeyPem.getBytes(StandardCharsets.UTF_8).length
                > MAX_PROXY_IDENTITY_PUBLIC_KEY_BYTES) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Web 返回的 Proxy 身份公钥大小无效");
        }
        String begin = "-----BEGIN PUBLIC KEY-----";
        String end = "-----END PUBLIC KEY-----";
        String normalized = publicKeyPem.trim();
        if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Web 返回的 Proxy 身份公钥格式无效");
        }
        String encoded = normalized.substring(
                begin.length(),
                normalized.length() - end.length()).replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            int bits = key.getModulus().bitLength();
            if (bits < 2048 || bits > 8192) {
                throw new AgentAuthClient.AuthException(
                        "Proxy Web 返回的 Proxy 身份公钥强度无效");
            }
        } catch (IllegalArgumentException
                 | GeneralSecurityException
                 | ClassCastException error) {
            throw new AgentAuthClient.AuthException(
                    "Proxy Web 返回的 Proxy 身份公钥格式无效",
                    error);
        }
    }
}
