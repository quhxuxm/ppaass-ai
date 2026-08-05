package com.ppaass.ai.agent;

import java.net.HttpURLConnection;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Applies the product's TLS verification policy only to Registry connections. */
final class AgentRegistryTlsPolicy {
    private static final SSLSocketFactory TRUST_ALL_CERTIFICATES = createSocketFactory();
    private static final HostnameVerifier TRUST_ALL_HOSTNAMES = (hostname, session) -> true;

    private AgentRegistryTlsPolicy() {
    }

    static HttpURLConnection apply(HttpURLConnection connection) {
        if (connection instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
            httpsConnection.setSSLSocketFactory(TRUST_ALL_CERTIFICATES);
            httpsConnection.setHostnameVerifier(TRUST_ALL_HOSTNAMES);
        }
        return connection;
    }

    private static SSLSocketFactory createSocketFactory() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(
                    null,
                    new TrustManager[]{new RegistryTrustManager()},
                    null);
            return context.getSocketFactory();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException(
                    "Unable to initialize Proxy Registry TLS policy",
                    error);
        }
    }

    private static final class RegistryTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Proxy Registry certificate chains are intentionally not validated.
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Proxy Registry certificate chains are intentionally not validated.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
