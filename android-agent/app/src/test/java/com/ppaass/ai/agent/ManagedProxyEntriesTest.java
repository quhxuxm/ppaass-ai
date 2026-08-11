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
        AgentAuthDtos.ProxyEntry backup = new AgentAuthDtos.ProxyEntry();
        backup.proxy_entry_id = "pxy_tokyo";
        backup.label = "Tokyo Edge";
        backup.description = "entry-jp · v1.2.3";
        backup.icon_key = "entry-jp";
        backup.address = "proxy-jp.example:80";
        backup.online = true;

        ManagedProxyEntries.Selection selection = ManagedProxyEntries.require(
                List.of(value, backup),
                List.of("pxy_singapore", "pxy_tokyo"),
                true);

        assertEquals(List.of("pxy_singapore", "pxy_tokyo"), selection.selectedIds);
        assertEquals("Singapore Edge", selection.entries.get(0).name);
        assertEquals("entry-sg · v1.2.3", selection.entries.get(0).description);
        assertTrue(selection.entries.get(0).online);
    }

    @Test(expected = AgentAuthClient.AuthException.class)
    public void catalogIsRejectedWhenPermissionIsMissing() throws Exception {
        ManagedProxyEntries.require(List.of(), null, false);
    }
}
