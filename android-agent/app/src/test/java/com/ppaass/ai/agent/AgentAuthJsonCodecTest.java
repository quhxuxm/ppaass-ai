package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class AgentAuthJsonCodecTest {
    @Test
    public void nativeLoginResponseMapsToExplicitCredentialDto() throws Exception {
        AgentAuthDtos.CredentialResponse response = AgentAuthJsonCodec.decode(
                loginJson().getBytes(StandardCharsets.UTF_8),
                AgentAuthDtos.CredentialResponse.class);

        assertEquals("admin", response.account.role);
        assertEquals("alice", response.profile.username);
        assertEquals(
                AgentPermissions.PACKET_CAPTURE,
                response.profile.permissions.get(0));
        assertEquals(
                "proxy-a.example:80",
                response.profile.proxy_addresses.get(0));
        assertEquals("private-material", response.private_key_pem);
        assertEquals("access_token_123", response.agent_access_token);
        assertEquals(Long.valueOf(300), response.refresh_after_seconds);
    }

    @Test
    public void synchronizedProfileUsesTypedPermissionsAndClampsInterval()
            throws Exception {
        String json = "{"
                + "\"account\":{\"role\":\"user\",\"status\":\"disabled\","
                + "\"linked_username\":\"alice\"},"
                + "\"profile\":{\"username\":\"alice\",\"permissions\":["
                + "\"agent.egress.edit\"],"
                + "\"proxy_addresses\":[\"proxy-a.example:80\"],\"enabled\":false,"
                + "\"key_version\":4,\"expires_at\":null},"
                + "\"key_state\":\"disabled\","
                + "\"agent_access_token\":\"rotated_token_456\","
                + "\"agent_access_token_expires_at\":4102444800,"
                + "\"refresh_after_seconds\":2}";
        AgentAuthDtos.ProfileSyncResponse response = AgentAuthJsonCodec.decode(
                json.getBytes(StandardCharsets.UTF_8),
                AgentAuthDtos.ProfileSyncResponse.class);
        AgentAuthClient.ProfileSyncResult parsed =
                AgentAuthResponseParser.parseProfileSync(response, "alice");

        assertEquals("disabled", parsed.accountStatus);
        assertFalse(parsed.profileEnabled);
        assertTrue(parsed.permissions.contains(AgentPermissions.EGRESS_EDIT));
        assertEquals(
                "proxy-a.example:80",
                parsed.proxyAddresses.get(0));
        assertEquals(AgentAuthResponseParser.MIN_REFRESH_SECONDS,
                parsed.refreshAfterSeconds);
    }

    @Test
    public void scalarCoercionAndDuplicateSensitiveFieldsAreRejected() {
        String coerced = "{\"account\":{\"role\":7}}";
        String duplicate = "{\"agent_access_token\":\"first\","
                + "\"agent_access_token\":\"second\"}";
        String trailingDocument = "{} {}";

        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentAuthJsonCodec.decode(
                        coerced.getBytes(StandardCharsets.UTF_8),
                        AgentAuthDtos.CredentialResponse.class));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentAuthJsonCodec.decode(
                        duplicate.getBytes(StandardCharsets.UTF_8),
                        AgentAuthDtos.CredentialResponse.class));
        assertThrows(
                AgentAuthClient.AuthException.class,
                () -> AgentAuthJsonCodec.decode(
                        trailingDocument.getBytes(StandardCharsets.UTF_8),
                        AgentAuthDtos.CredentialResponse.class));
    }

    @Test
    public void passwordRequestDoesNotExposeSecretsThroughToString() {
        AgentAuthDtos.PasswordLoginRequest request =
                new AgentAuthDtos.PasswordLoginRequest("alice", "secret-password");
        assertFalse(request.toString().contains("secret-password"));
    }

    @Test
    public void typedApiErrorEnvelopeMapsWithoutParsingResponseTextManually() {
        byte[] body = ("{\"error\":{\"code\":\"invalid_credentials\","
                + "\"message\":\"ignored\"}}").getBytes(StandardCharsets.UTF_8);
        assertEquals(
                "用户名或密码错误",
                AgentAuthErrors.apiError(401, body).getMessage());
    }

    @Test
    public void webSessionHandoffUsesTypedJacksonDto() throws Exception {
        byte[] body = ("{\"handoff_path\":\"/api/v1/auth/agent-handoff?code=once\","
                + "\"expires_in\":90}").getBytes(StandardCharsets.UTF_8);

        AgentAuthDtos.WebSessionHandoffResponse response = AgentAuthJsonCodec.decode(
                body,
                AgentAuthDtos.WebSessionHandoffResponse.class);

        assertEquals(
                "/api/v1/auth/agent-handoff?code=once",
                response.handoff_path);
        assertEquals(Long.valueOf(90), response.expires_in);
    }

    private static String loginJson() {
        return "{"
                + "\"account\":{\"role\":\"admin\",\"status\":\"active\","
                + "\"linked_username\":\"alice\"},"
                + "\"profile\":{\"username\":\"alice\",\"permissions\":["
                + "\"agent.packet_capture\"],"
                + "\"proxy_addresses\":[\"proxy-a.example:80\"],\"enabled\":true,"
                + "\"key_version\":4,\"expires_at\":4102444800},"
                + "\"public_key_pem\":\"public-material\","
                + "\"private_key_pem\":\"private-material\","
                + "\"proxy_identity_public_key_pem\":\"proxy-identity\","
                + "\"agent_access_token\":\"access_token_123\","
                + "\"agent_access_token_expires_at\":4102444800,"
                + "\"refresh_after_seconds\":300}";
    }
}
