package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class AgentAdminClientTest {
    private static final String TOKEN = "agent_admin_token";

    @Test
    public void dashboardUsesBearerAndTypedJacksonModels() throws Exception {
        FakeTransport transport = new FakeTransport(
                ok(keyRequestsJson("pending")),
                ok(proxyAddressesJson()));
        AgentAdminModels.Dashboard dashboard =
                new AgentAdminClient(transport).loadDashboard(TOKEN);

        assertEquals(2, transport.calls.size());
        assertEquals("GET", transport.calls.get(0).method);
        assertEquals(
                AgentAdminClient.KEY_REQUESTS_PATH,
                transport.calls.get(0).path);
        assertEquals(TOKEN, transport.calls.get(0).bearerToken);
        assertEquals(
                AgentAdminClient.PROXY_ADDRESSES_PATH,
                transport.calls.get(1).path);
        assertEquals(1, dashboard.requests.size());
        AgentAdminModels.KeyRequest request = dashboard.requests.get(0);
        assertEquals("req_one", request.id);
        assertEquals("alice@example.com", request.username);
        assertEquals(
                "data:image/png;base64,iVBORw0KGgo=",
                request.avatarUrl);
        assertEquals("需要续期", request.message);
        assertEquals(List.of("proxy_main"), request.proxyAddressIds);
        assertEquals(1, dashboard.proxyAddresses.size());
        assertTrue(dashboard.proxyAddresses.get(0).enabled);
    }

    @Test
    public void registeredEntryMetadataDoesNotInvalidateProxyCatalog()
            throws Exception {
        FakeTransport transport = new FakeTransport(ok(proxyAddressesJson()));

        List<AgentAdminModels.ProxyAddress> addresses =
                new AgentAdminClient(transport).listProxyAddresses(TOKEN);

        assertEquals(1, addresses.size());
        assertEquals("proxy_main", addresses.get(0).id);
        assertEquals("140.82.30.214:80", addresses.get(0).address);
        assertTrue(addresses.get(0).enabled);
    }

    @Test
    public void approvalSendsFutureExpiryAndSelectedProxyIds() throws Exception {
        FakeTransport transport = new FakeTransport(ok(keyRequestsJson("approved")));
        AgentAdminClient client = new AgentAdminClient(transport);

        client.approve(
                TOKEN,
                "req_one",
                4_102_444_800L,
                List.of("proxy_main"),
                " 已核实用途 ");

        Call call = transport.calls.get(0);
        assertEquals("POST", call.method);
        assertEquals(
                AgentAdminClient.KEY_REQUESTS_PATH + "/req_one/approve",
                call.path);
        AgentAdminDtos.ApproveKeyRequest body =
                (AgentAdminDtos.ApproveKeyRequest) call.body;
        assertEquals(4_102_444_800L, body.expires_at);
        assertEquals(List.of("proxy_main"), body.proxy_address_ids);
        assertEquals("已核实用途", body.reason);
    }

    @Test
    public void rejectionPostsUserVisibleReason() throws Exception {
        FakeTransport transport = new FakeTransport(ok(keyRequestsJson("rejected")));

        new AgentAdminClient(transport).reject(TOKEN, "req_one", " 请补充用途 ");

        Call call = transport.calls.get(0);
        assertEquals(
                AgentAdminClient.KEY_REQUESTS_PATH + "/req_one/reject",
                call.path);
        AgentAdminDtos.RejectKeyRequest body =
                (AgentAdminDtos.RejectKeyRequest) call.body;
        assertEquals("请补充用途", body.reason);
    }

    @Test
    public void conflictRemainsDistinguishableForAutomaticRefresh() {
        FakeTransport transport = new FakeTransport(response(
                409,
                "{\"error\":{\"code\":\"key_request_already_reviewed\","
                        + "\"message\":\"密钥申请已被处理\"}}"));

        AgentAdminClient.AdminException error = assertThrows(
                AgentAdminClient.AdminException.class,
                () -> new AgentAdminClient(transport).reject(
                        TOKEN,
                        "req_one",
                        "申请材料不足"));

        assertTrue(error.isConflict());
        assertEquals("key_request_already_reviewed", error.code);
    }

    @Test
    public void malformedOrDuplicatePendingRequestsFailClosed() {
        String duplicate = "{\"requests\":["
                + keyRequestObject("pending") + ","
                + keyRequestObject("pending") + "]}";
        FakeTransport transport = new FakeTransport(ok(duplicate));

        AgentAdminClient.AdminException error = assertThrows(
                AgentAdminClient.AdminException.class,
                () -> new AgentAdminClient(transport).listKeyRequests(TOKEN));

        assertEquals("invalid_response", error.code);
        assertFalse(error.isConflict());
    }

    private static AgentAuthHttpTransport.Response ok(String body) {
        return response(200, body);
    }

    private static AgentAuthHttpTransport.Response response(
            int status,
            String body) {
        return new AgentAuthHttpTransport.Response(
                status,
                body.getBytes(StandardCharsets.UTF_8),
                0);
    }

    private static String keyRequestsJson(String status) {
        return status.equals("pending")
                ? "{\"requests\":[" + keyRequestObject(status) + "]}"
                : "{\"request\":" + keyRequestObject(status)
                + ",\"user\":null}";
    }

    private static String keyRequestObject(String status) {
        return "{"
                + "\"request_id\":\"req_one\","
                + "\"account\":{\"account_id\":\"acc_alice\","
                + "\"login_name\":\"alice@example.com\","
                + "\"display_name\":\"Alice\","
                + "\"avatar_url\":\"data:image/png;base64,iVBORw0KGgo=\","
                + "\"email\":\"alice@example.com\"},"
                + "\"proxy_address_ids\":[\"proxy_main\"],"
                + "\"request_message\":\"需要续期\","
                + "\"kind\":\"rotate\",\"status\":\"" + status + "\","
                + "\"requested_at\":1770000000"
                + "}";
    }

    private static String proxyAddressesJson() {
        return "{\"proxy_addresses\":[{"
                + "\"proxy_address_id\":\"proxy_main\","
                + "\"label\":\"生产 Proxy\","
                + "\"address\":\"140.82.30.214:80\","
                + "\"enabled\":true,"
                + "\"created_at\":1770000000,"
                + "\"updated_at\":1770000300,"
                + "\"entry_id\":\"entry_production_1\","
                + "\"entry_version\":\"1.2.3\","
                + "\"entry_first_registered_at\":1770000000,"
                + "\"entry_last_heartbeat_at\":1770000300,"
                + "\"entry_online\":true"
                + "}]}";
    }

    private static final class FakeTransport
            implements AgentAdminClient.Transport {
        final List<Call> calls = new ArrayList<>();
        final List<AgentAuthHttpTransport.Response> responses;
        boolean cancelled;

        FakeTransport(AgentAuthHttpTransport.Response... responses) {
            this.responses = new ArrayList<>(List.of(responses));
        }

        @Override
        public AgentAuthHttpTransport.Response execute(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) {
            calls.add(new Call(method, path, body, bearerToken, maximumBytes));
            return responses.remove(0);
        }

        @Override
        public void cancel() {
            cancelled = true;
        }
    }

    private static final class Call {
        final String method;
        final String path;
        final Object body;
        final String bearerToken;
        final int maximumBytes;

        Call(
                String method,
                String path,
                Object body,
                String bearerToken,
                int maximumBytes) {
            this.method = method;
            this.path = path;
            this.body = body;
            this.bearerToken = bearerToken;
            this.maximumBytes = maximumBytes;
        }
    }
}
