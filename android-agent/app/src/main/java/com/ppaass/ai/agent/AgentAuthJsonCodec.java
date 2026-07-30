package com.ppaass.ai.agent;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.type.LogicalType;

import java.io.IOException;

final class AgentAuthJsonCodec {
    private static final ObjectMapper MAPPER = createMapper();

    private AgentAuthJsonCodec() {
    }

    static byte[] encode(Object value) throws AgentAuthClient.AuthException {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException error) {
            throw new AgentAuthClient.AuthException("无法创建认证请求", error);
        }
    }

    static <T> T decode(byte[] bytes, Class<T> responseType)
            throws AgentAuthClient.AuthException {
        if (bytes == null || bytes.length == 0) {
            throw invalidResponse(null);
        }
        try {
            return MAPPER.readValue(bytes, responseType);
        } catch (IOException | RuntimeException error) {
            throw invalidResponse(error);
        }
    }

    static <T> T decodeError(byte[] bytes, Class<T> responseType) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        try {
            return MAPPER.readValue(bytes, responseType);
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        mapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        mapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        mapper.coercionConfigFor(LogicalType.Textual)
                .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail);
        mapper.coercionConfigFor(LogicalType.Integer)
                .setCoercion(CoercionInputShape.String, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Float, CoercionAction.Fail);
        mapper.coercionConfigFor(LogicalType.Boolean)
                .setCoercion(CoercionInputShape.String, CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
        return mapper;
    }

    private static AgentAuthClient.AuthException invalidResponse(Throwable cause) {
        return cause == null
                ? new AgentAuthClient.AuthException("Proxy Registry 响应格式无效")
                : new AgentAuthClient.AuthException("Proxy Registry 响应格式无效", cause);
    }
}
