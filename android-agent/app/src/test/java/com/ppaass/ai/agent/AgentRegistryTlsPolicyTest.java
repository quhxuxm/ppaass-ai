package com.ppaass.ai.agent;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

public final class AgentRegistryTlsPolicyTest {
    @Test
    public void httpsUsesInstancePolicyWithoutChangingGlobalDefaults()
            throws Exception {
        SSLSocketFactory globalFactory =
                HttpsURLConnection.getDefaultSSLSocketFactory();
        HostnameVerifier globalVerifier =
                HttpsURLConnection.getDefaultHostnameVerifier();
        FakeHttpsConnection connection = new FakeHttpsConnection(
                new URL("https://registry.example.com"));
        SSLSocketFactory originalFactory = connection.getSSLSocketFactory();
        HostnameVerifier originalVerifier = connection.getHostnameVerifier();

        assertSame(connection, AgentRegistryTlsPolicy.apply(connection));

        assertNotSame(originalFactory, connection.getSSLSocketFactory());
        assertNotSame(originalVerifier, connection.getHostnameVerifier());
        assertTrue(connection.getHostnameVerifier().verify(
                "unrelated.example",
                null));
        assertSame(globalFactory, HttpsURLConnection.getDefaultSSLSocketFactory());
        assertSame(globalVerifier, HttpsURLConnection.getDefaultHostnameVerifier());
    }

    @Test
    public void plainHttpConnectionIsReturnedUnchanged() throws Exception {
        FakeHttpConnection connection = new FakeHttpConnection(
                new URL("http://registry.example.com"));

        assertSame(connection, AgentRegistryTlsPolicy.apply(connection));
    }

    private static final class FakeHttpsConnection extends HttpsURLConnection {
        FakeHttpsConnection(URL url) {
            super(url);
        }

        @Override
        public String getCipherSuite() {
            return "";
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return null;
        }

        @Override
        public Certificate[] getServerCertificates()
                throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public void disconnect() {
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() throws IOException {
        }
    }

    private static final class FakeHttpConnection extends HttpURLConnection {
        FakeHttpConnection(URL url) {
            super(url);
        }

        @Override
        public void disconnect() {
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() throws IOException {
        }
    }
}
