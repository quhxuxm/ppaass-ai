import assert from "node:assert/strict";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "error",
  server: { middlewareMode: true }
});

try {
  const { applyFieldToToml, coerceField, summarizeRaw } = await server.ssrLoadModule("/src/configToml.ts");
  const { transportModeOptions } = await server.ssrLoadModule("/src/constants.ts");

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
  assert.throws(() => summarizeRaw("quic_connection_pool_size = 4\n"), /已移除/);
  assert.equal(summarizeRaw("udp_session_pool_size = 0\n").udp_session_pool_size, 1);
  assert.equal(summarizeRaw("udp_session_pool_size = 99\n").udp_session_pool_size, 8);
  assert.equal(coerceField("udp_session_pool_size", 0), 1);
  assert.equal(coerceField("udp_session_pool_size", 99), 8);

  const updated = applyFieldToToml(
    'transport_mode = "udp"\n',
    "udp_session_pool_size",
    coerceField("udp_session_pool_size", 6)
  );
  assert.match(updated, /^udp_session_pool_size = 6$/m);
  assert.equal(summarizeRaw(updated).udp_session_pool_size, 6);
} finally {
  await server.close();
}

console.log("configToml tests passed");
