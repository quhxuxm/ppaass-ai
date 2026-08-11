import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "error",
  optimizeDeps: { noDiscovery: true },
  server: { middlewareMode: true }
});

const originalWarn = console.warn;
console.warn = (...args) => {
  if (
    !String(args[0]).includes(
      "called when there is no active component instance"
    )
  ) {
    originalWarn(...args);
  }
};

try {
  const {
    AGENT_PERMISSION_CODES,
    hasAgentPermission,
    resolveAgentCapabilities
  } = await server.ssrLoadModule("/src/agentPermissions.ts");

  assert.deepEqual(Object.values(AGENT_PERMISSION_CODES), [
    "agent.packet_capture",
    "agent.egress.edit",
    "agent.runtime_threads.edit",
    "agent.proxy_entry.select"
  ]);

  const ordinaryUser = { role: "user", permissions: [] };
  assert.deepEqual(resolveAgentCapabilities(ordinaryUser), {
    canCapturePackets: false,
    canViewRawConfig: false,
    canEditEgress: false,
    canEditRuntimeThreads: false,
    canSelectProxyEntry: false
  });
  assert.equal(
    hasAgentPermission(
      { role: "user", permissions: ["agent.egress.edit"] },
      AGENT_PERMISSION_CODES.egressEdit
    ),
    true
  );
  assert.deepEqual(
    Object.values(
      resolveAgentCapabilities({ role: "admin", permissions: [] })
    ),
    [true, true, true, true, true]
  );

  const { summarizeRaw } = await server.ssrLoadModule(
    "/src/configToml.ts"
  );
  const { useDesktopAgent } = await server.ssrLoadModule(
    "/src/composables/useDesktopAgent.ts"
  );
  const restrictedAgent = useDesktopAgent({
    canUsePacketCapture: () => false,
    canViewRawConfig: () => false
  });
  const initialRaw = "";
  restrictedAgent.state.config = {
    path: "/tmp/agent.toml",
    raw: initialRaw,
    summary: summarizeRaw('compression_mode = "none"\n')
  };
  restrictedAgent.setField("compression_mode", "gzip");
  assert.equal(
    restrictedAgent.state.config.summary.compression_mode,
    "gzip"
  );
  assert.equal(restrictedAgent.state.config.raw, initialRaw);
  restrictedAgent.setRawConfig('compression_mode = "zstd"\n');
  assert.equal(restrictedAgent.state.config.raw, initialRaw);

  const { createDesktopAgentModel } = await server.ssrLoadModule(
    "/src/composables/desktopAgent/model.ts"
  );
  const { createRuntimeController } = await server.ssrLoadModule(
    "/src/composables/desktopAgent/runtimeController.ts"
  );
  const runtimeMessages = [];
  const runtimeModel = createDesktopAgentModel();
  const restrictedRuntime = createRuntimeController(runtimeModel, {
    canUsePacketCapture: () => false,
    persistConfig: async () => {},
    showToast: (kind, message) => {
      runtimeMessages.push({ kind, message });
    }
  });
  await restrictedRuntime.togglePacketCapture(true);
  await restrictedRuntime.clearPacketCapture();
  assert.deepEqual(runtimeMessages, [
    {
      kind: "error",
      message: "当前账户没有使用抓包功能的权限"
    },
    {
      kind: "error",
      message: "当前账户没有使用抓包功能的权限"
    }
  ]);
  assert.equal(runtimeModel.state.packetCapture.enabled, false);

  const workspace = await readFile(
    new URL("../src/AgentWorkspace.vue", import.meta.url),
    "utf8"
  );
  assert.match(workspace, /resolveAgentCapabilities\(props\.account\)/);
  assert.match(workspace, /tab\.key !== "capture"/);
  assert.match(workspace, /tab\.key !== "egress"/);
  assert.match(workspace, /tab\.key !== "toml"/);
  assert.match(workspace, /@update:active-tab="setActiveTab"/);
  assert.match(workspace, /togglePermittedPacketCapture/);
  assert.match(workspace, /clearPermittedPacketCapture/);
  assert.match(
    workspace,
    /:can-edit-egress="capabilities\.canEditEgress"/
  );
  assert.match(
    workspace,
    /:can-edit-runtime-threads="capabilities\.canEditRuntimeThreads"/
  );
  assert.match(workspace, /<ProxyEntrySelector/);
  assert.match(
    workspace,
    /v-if="capabilities\.canSelectProxyEntry && accountStatus === 'active'"/
  );

  const proxySelector = await readFile(
    new URL("../src/components/ProxyEntrySelector.vue", import.meta.url),
    "utf8"
  );
  assert.match(proxySelector, /entry\.icon_key/);
  assert.match(proxySelector, /entry\.label/);
  assert.match(proxySelector, /entry\.description/);
  assert.doesNotMatch(proxySelector, /entry\.address|IP 地址|连接地址/);
  assert.match(proxySelector, /@click\.stop="runSpeedTest\(entry\)"/);

  const proxySelection = await readFile(
    new URL(
      "../src/composables/useProxyEntrySelection.ts",
      import.meta.url
    ),
    "utf8"
  );
  assert.match(proxySelection, /"speed_test_agent_proxy_entry"/);
  assert.match(proxySelection, /"select_agent_proxy_entry_command"/);
  assert.match(proxySelection, /pendingIds\.value/);
  assert.match(proxySelection, /proxyEntryIds: pendingIds\.value/);
  assert.match(proxySelection, /visible\.value = false/);

  const proxyStyles = await readFile(
    new URL("../src/styles/proxy-entry-selector.css", import.meta.url),
    "utf8"
  );
  assert.match(proxyStyles, /height: min\(680px, calc\(100dvh - 64px\)\)/);
  assert.match(proxyStyles, /overflow-y: auto/);
  assert.match(proxyStyles, /scrollbar-gutter: stable/);
  assert.match(proxyStyles, /grid-auto-rows: 124px/);
  assert.match(proxyStyles, /height: 124px/);
  assert.match(proxyStyles, /min-height: 116px/);
  assert.doesNotMatch(proxyStyles, /grid-column:\s*1\s*\/\s*-1/);

  const authComposable = await readFile(
    new URL("../src/composables/useAgentAuth.ts", import.meta.url),
    "utf8"
  );
  assert.match(
    authComposable,
    /listen<AgentAuthState>\("agent-auth-state-updated"/
  );
  assert.match(authComposable, /permission_sync_error/);
  assert.match(authComposable, /applyAuthState\(event\.payload\)/);
  assert.match(authComposable, /auth\.account_status = status/);

  const app = await readFile(
    new URL("../src/App.vue", import.meta.url),
    "utf8"
  );
  assert.match(app, /account\.role/);
  assert.match(app, /\.\.\.account\.permissions/);

  const bootstrap = await readFile(
    new URL("../src-tauri/src/app/bootstrap.rs", import.meta.url),
    "utf8"
  );
  assert.match(bootstrap, /start_agent_server_events/);
  assert.doesNotMatch(bootstrap, /WindowEvent::Focused\(true\)/);
  assert.doesNotMatch(bootstrap, /permission_sync_notify/);

  const serverEvents = await readFile(
    new URL("../src-tauri/src/app/server_events.rs", import.meta.url),
    "utf8"
  );
  assert.match(serverEvents, /AgentServerEventStream::connect/);
  assert.match(serverEvents, /AdminKeyRequestsChanged/);
  assert.doesNotMatch(serverEvents, /interval\(/);

  const egress = await readFile(
    new URL("../src/views/EgressView.vue", import.meta.url),
    "utf8"
  );
  for (const field of [
    "transport_mode",
    "connect_timeout_secs",
    "compression_mode",
    "udp_session_pool_size",
    "udp_yamux_sessions",
    "udp_yamux_max_streams_per_session",
    "udp_yamux_open_stream_timeout_secs",
    "udp_yamux_keepalive_interval_secs",
    "udp_yamux_connection_write_timeout_secs",
    "udp_yamux_stream_window_size_kb"
  ]) {
    assert.match(egress, new RegExp(`"${field}"`));
  }
  assert.doesNotMatch(egress, /proxy_addrs|远端出口地址/);
  assert.match(
    egress,
    /protectedEgressFields\.has\(field\)/
  );
  assert.ok(
    egress.match(/:disabled="configLocked \|\| !canEditEgress"/g)
      ?.length >= 4
  );
  assert.doesNotMatch(egress, /没有出口配置编辑权限/);

  const routing = await readFile(
    new URL("../src/views/RoutingView.vue", import.meta.url),
    "utf8"
  );
  assert.match(routing, /v-if="canEditRuntimeThreads"/);
  assert.match(
    routing,
    /:disabled="configLocked"/
  );
  assert.doesNotMatch(routing, /没有修改系统线程数的权限/);

  const forwarding = await readFile(
    new URL("../src/views/ForwardingView.vue", import.meta.url),
    "utf8"
  );
  const capture = await readFile(
    new URL("../src/views/PacketCaptureView.vue", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(forwarding, /明文抓包|tun_packet_capture_file/);
  assert.match(capture, /<h2>明文抓包<\/h2>/);
  assert.match(capture, /summary\.tun_packet_capture_file/);
  assert.match(capture, /emit\('set-field', 'tun_packet_capture_file'/);

  const configController = await readFile(
    new URL(
      "../src/composables/desktopAgent/configController.ts",
      import.meta.url
    ),
    "utf8"
  );
  assert.match(configController, /"save_agent_config_summary"/);
  assert.match(
    configController,
    /summary: state\.config\.summary/
  );

  const runtimeController = await readFile(
    new URL(
      "../src/composables/desktopAgent/runtimeController.ts",
      import.meta.url
    ),
    "utf8"
  );
  assert.ok(
    runtimeController.match(
      /if \(!dependencies\.canUsePacketCapture\(\)\)/g
    )?.length >= 2
  );
  assert.match(
    runtimeController,
    /state\.agent\.running && dependencies\.canUsePacketCapture\(\)/
  );
} finally {
  console.warn = originalWarn;
  await server.close();
}

console.log("agentPermissions tests passed");
