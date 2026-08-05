import assert from "node:assert/strict";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "error",
  optimizeDeps: { noDiscovery: true },
  server: { middlewareMode: true }
});

try {
  const { applyFieldToToml, coerceField, summarizeRaw } = await server.ssrLoadModule("/src/configToml.ts");
  const { transportModeOptions } = await server.ssrLoadModule("/src/constants.ts");
  const { connectivityResultLabel, dnsRecordMatchesFilter } =
    await server.ssrLoadModule("/src/formatters.ts");

  assert.equal(connectivityResultLabel({ success: true, http_code: 204 }), "204");
  assert.equal(connectivityResultLabel({ success: true, http_code: null }), "通过");
  assert.equal(connectivityResultLabel({ success: false, http_code: null }), "失败");

  const dnsRecord = {
    timestamp_ms: 1,
    resolver: "agent-cache",
    client: "client-a",
    upstream: "8.8.8.8:53",
    query: "api.example.com",
    record_type: "A",
    status: "NOERROR",
    answers: ["203.0.113.8"],
    duration_ms: 12
  };
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "EXAMPLE 203.0.113"), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "client-a 成功"), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "缓存命中"), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "cache hit"), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "已直连", ["已直连 direct"]), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "direct", ["已直连 direct"]), true);
  assert.equal(dnsRecordMatchesFilter(dnsRecord, "TIMEOUT"), false);
  assert.equal(
    dnsRecordMatchesFilter({ ...dnsRecord, status: undefined }, "api.example.com"),
    true
  );

  assert.deepEqual(transportModeOptions, [
    { label: "自动模式", value: "auto" },
    { label: "原生 UDP 模式", value: "udp" },
    { label: "全 TCP 模式", value: "tcp" }
  ]);

  const udpSummary = summarizeRaw('transport_mode = "udp"\n');
  const autoSummary = summarizeRaw('transport_mode = "auto"\n');
  const fullTcpSummary = summarizeRaw('transport_mode = "tcp"\n');
  assert.equal(udpSummary.transport_mode, "udp");
  assert.equal(autoSummary.transport_mode, "auto");
  assert.equal(udpSummary.udp_session_pool_size, 4);
  assert.equal(fullTcpSummary.transport_mode, "tcp");
  assert.throws(() => coerceField("transport_mode", "unknown"), /auto、udp 或 tcp/);
  assert.throws(() => summarizeRaw('transport_mode = "quic"\n'), /auto、udp 或 tcp/);
  assert.throws(
    () => summarizeRaw('proxy_addrs = ["proxy.example.com:443"]\n'),
    /Proxy 地址只能由登录会话下发/
  );
  assert.throws(() => summarizeRaw("quic_connection_pool_size = 4\n"), /已移除/);
  assert.throws(
    () => summarizeRaw("[tun]\nhelper_enabled = true\n"),
    /macos_helper_enabled/
  );
  assert.throws(
    () => summarizeRaw('[tun]\nhelper_socket = "/tmp/helper.sock"\n'),
    /macos_helper_socket/
  );
  assert.throws(
    () => summarizeRaw("[tun]\nhelper_fallback_to_privilege = true\n"),
    /macos_helper_fallback_to_privilege/
  );
  assert.equal(summarizeRaw("udp_session_pool_size = 0\n").udp_session_pool_size, 1);
  assert.equal(summarizeRaw("udp_session_pool_size = 99\n").udp_session_pool_size, 8);
  assert.equal(coerceField("udp_session_pool_size", 0), 1);
  assert.equal(coerceField("udp_session_pool_size", 99), 8);
  assert.equal(udpSummary.tun_packet_capture_file, "captures/ppaass-tun.pcap");
  assert.equal(summarizeRaw("[tun]\nenabled = true\n").tun_proxy_dns, true);
  assert.equal(
    summarizeRaw("[tun]\nenabled = true\nproxy_dns = false\n").tun_proxy_dns,
    false
  );
  const editedDefaultTun = applyFieldToToml(
    "[tun]\nenabled = true\n",
    "log_level",
    "debug"
  );
  assert.equal(summarizeRaw(editedDefaultTun).tun_proxy_dns, true);
  assert.doesNotMatch(editedDefaultTun, /proxy_dns\s*=\s*false/);

  const updated = applyFieldToToml(
    'transport_mode = "udp"\n',
    "udp_session_pool_size",
    coerceField("udp_session_pool_size", 6)
  );
  assert.match(updated, /^udp_session_pool_size = 6$/m);
  assert.equal(summarizeRaw(updated).udp_session_pool_size, 6);

  const captureUpdated = applyFieldToToml(updated, "tun_packet_capture_file", "captures/debug.pcap");
  assert.equal(summarizeRaw(captureUpdated).tun_packet_capture_file, "captures/debug.pcap");
} finally {
  await server.close();
}

console.log("configToml tests passed");

await import("./test-managed-private-key.mjs");
