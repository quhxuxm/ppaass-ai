package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class AgentAdminApprovalDialogTest {
    @Test
    public void approvalRequiresFutureExpiryAndAtLeastOneProxy() {
        assertEquals(
                "密钥过期时间必须晚于当前时间",
                AgentAdminApprovalDialog.validationMessage(100, 100, 1));
        assertEquals(
                "请至少选择一个启用的 Proxy 地址",
                AgentAdminApprovalDialog.validationMessage(100, 101, 0));
        assertNull(AgentAdminApprovalDialog.validationMessage(100, 101, 1));
    }
}
