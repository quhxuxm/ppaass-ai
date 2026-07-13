import assert from "node:assert/strict";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "error",
  server: { middlewareMode: true }
});

try {
  const { applyFieldToToml, coerceField, summarizeRaw } = await server.ssrLoadModule("/src/configToml.ts");

  assert.equal(summarizeRaw('transport_mode = "quic"\n').quic_connection_pool_size, 4);
  assert.equal(summarizeRaw("quic_connection_pool_size = 0\n").quic_connection_pool_size, 1);
  assert.equal(summarizeRaw("quic_connection_pool_size = 99\n").quic_connection_pool_size, 8);
  assert.equal(coerceField("quic_connection_pool_size", 0), 1);
  assert.equal(coerceField("quic_connection_pool_size", 99), 8);

  const updated = applyFieldToToml(
    'transport_mode = "quic"\n',
    "quic_connection_pool_size",
    coerceField("quic_connection_pool_size", 6)
  );
  assert.match(updated, /^quic_connection_pool_size = 6$/m);
  assert.equal(summarizeRaw(updated).quic_connection_pool_size, 6);
} finally {
  await server.close();
}

console.log("configToml tests passed");
