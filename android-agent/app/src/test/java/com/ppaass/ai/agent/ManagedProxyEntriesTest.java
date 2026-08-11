package com.ppaass.ai.agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;

public final class ManagedProxyEntriesTest {
    @Test
    public void permittedCatalogKeepsPresentationMetadataSeparateFromAddress() throws Exception {
        AgentAuthDtos.ProxyEntry value = new AgentAuthDtos.ProxyEntry();
        value.proxy_entry_id = "pxy_singapore";
        value.label = "Singapore Edge";
        value.description = "entry-sg · v1.2.3";
        value.icon_key = "entry-sg";
        value.address = "proxy-sg.example:443";
        value.online = true;

        ManagedProxyEntries.Selection selection = ManagedProxyEntries.require(
                List.of(value),
                "pxy_singapore",
                true);

        assertEquals("pxy_singapore", selection.selectedId);
        assertEquals("Singapore Edge", selection.entries.get(0).name);
        assertEquals("entry-sg · v1.2.3", selection.entries.get(0).description);
        assertTrue(selection.entries.get(0).online);
    }

    @Test(expected = AgentAuthClient.AuthException.class)
    public void catalogIsRejectedWhenPermissionIsMissing() throws Exception {
        ManagedProxyEntries.require(List.of(), null, false);
    }
}
