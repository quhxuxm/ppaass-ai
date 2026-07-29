package com.ppaass.ai.agent;

final class AgentAuthErrors {
    private AgentAuthErrors() {
    }

    static AgentAuthClient.AuthException apiError(int status, byte[] responseBody) {
        AgentAuthDtos.ApiErrorEnvelope envelope = AgentAuthJsonCodec.decodeError(
                responseBody,
                AgentAuthDtos.ApiErrorEnvelope.class);
        String code = envelope == null || envelope.error == null
                ? ""
                : envelope.error.code;
        if ("invalid_credentials".equals(code)) {
            return new AgentAuthClient.AuthException("用户名或密码错误");
        }
        if ("key_request_required".equals(code)) {
            return new AgentAuthClient.AuthException(
                    "当前没有可用密钥，请先在用户中心提交申请并等待管理员批准");
        }
        if ("proxy_address_not_assigned".equals(code)) {
            return new AgentAuthClient.AuthException(
                    "管理员尚未为当前账户分配 Proxy 地址");
        }
        if ("unauthorized".equals(code)) {
            return new AgentAuthClient.AuthException(
                    "Agent 权限同步凭据已失效");
        }
        return new AgentAuthClient.AuthException("认证服务返回 HTTP " + status);
    }
}
