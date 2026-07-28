import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "vite";

const server = await createServer({
  appType: "custom",
  logLevel: "error",
  optimizeDeps: { noDiscovery: true },
  server: { middlewareMode: true }
});

try {
  const {
    deviceLoginRemainingSeconds,
    deviceLoginStatusText,
    devicePollDelayMilliseconds,
    formatDeviceLoginCountdown
  } = await server.ssrLoadModule("/src/deviceLogin.ts");

  assert.equal(devicePollDelayMilliseconds(5), 5000);
  assert.equal(devicePollDelayMilliseconds(0), 1000);
  assert.equal(devicePollDelayMilliseconds(999), 120000);
  assert.equal(devicePollDelayMilliseconds(Number.NaN), 1000);
  assert.equal(deviceLoginRemainingSeconds(610, 10_000), 600);
  assert.equal(deviceLoginRemainingSeconds(10, 10_001), 0);
  assert.equal(formatDeviceLoginCountdown(600), "10:00");
  assert.equal(formatDeviceLoginCountdown(9), "00:09");
  assert.match(deviceLoginStatusText("authorization_pending"), /系统浏览器/);
  assert.match(deviceLoginStatusText("slow_down"), /放慢/);

  const loginView = await readFile(
    new URL("../src/views/LoginView.vue", import.meta.url),
    "utf8"
  );
  assert.match(loginView, /label="使用浏览器登录"/);
  assert.doesNotMatch(loginView, /微信|WeChat|Google|oauth/i);
  assert.match(loginView, /label="取消设备登录"/);
  assert.match(loginView, /formatDeviceLoginCountdown\(deviceLoginRemaining\)/);
  assert.doesNotMatch(loginView, /proxyWebUrl|proxy_web_url|private_key_pem/);

  const composable = await readFile(
    new URL("../src/composables/useAgentAuth.ts", import.meta.url),
    "utf8"
  );
  assert.match(composable, /invoke<AgentDeviceLoginProgress>\(\s*"start_agent_device_login"/);
  assert.match(composable, /invoke<AgentDeviceLoginProgress>\(\s*"poll_agent_device_login"/);
  assert.match(composable, /invoke\("cancel_agent_device_login"\)/);
  assert.doesNotMatch(composable, /verification_uri|device_code|proxy_web_url|private_key_pem/);

  const appBackend = await readFile(
    new URL("../src-tauri/src/app.rs", import.meta.url),
    "utf8"
  );
  const deviceStartCommand = appBackend.slice(
    appBackend.indexOf("async fn start_agent_device_login"),
    appBackend.indexOf("async fn poll_agent_device_login")
  );
  assert.match(deviceStartCommand, /open_system_browser\(&verification_url\)/);
  assert.doesNotMatch(deviceStartCommand, /WebviewWindowBuilder|incognito/);

  const authBackend = await readFile(
    new URL("../src-tauri/src/auth.rs", import.meta.url),
    "utf8"
  );
  assert.match(authBackend, /platform:\s*"windows"/);
  assert.match(authBackend, /ShellExecuteW/);
  assert.match(authBackend, /best_effort_logout\(&client,\s*&base_url,\s*&csrf_token\)\.await/);
} finally {
  await server.close();
}

console.log("deviceLogin tests passed");
