import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const loginView = await readFile(
  new URL("../src/views/LoginView.vue", import.meta.url),
  "utf8"
);
assert.match(loginView, /label="登录并配置 Agent"/);
assert.match(loginView, /label="注册和账户管理"/);
assert.doesNotMatch(
  loginView,
  /使用浏览器登录|系统浏览器|设备登录|deviceLogin|device-login/
);
assert.doesNotMatch(loginView, /微信|WeChat|Google|oauth/i);
assert.doesNotMatch(loginView, /proxyRegistryUrl|proxy_registry_url|private_key_pem/);

const appView = await readFile(
  new URL("../src/App.vue", import.meta.url),
  "utf8"
);
assert.doesNotMatch(
  appView,
  /startDeviceLogin|cancelDeviceLogin|deviceLogin|device-login/
);

const composable = await readFile(
  new URL("../src/composables/useAgentAuth.ts", import.meta.url),
  "utf8"
);
assert.match(composable, /invoke\("open_user_account_management"\)/);
assert.doesNotMatch(
  composable,
  /start_agent_device_login|poll_agent_device_login|cancel_agent_device_login|DeviceLogin/
);
assert.doesNotMatch(
  composable,
  /verification_uri|device_code|proxy_registry_url|private_key_pem/
);

const loginCommands = await readFile(
  new URL("../src-tauri/src/app/login_commands.rs", import.meta.url),
  "utf8"
);
assert.match(loginCommands, /request_account_management_handoff/);
assert.match(loginCommands, /session\.proxy_registry_url/);
assert.match(loginCommands, /session\s*\.\s*agent_access_token/);
assert.match(loginCommands, /\.destroy\(\)/);
assert.doesNotMatch(
  loginCommands,
  /get_webview_window\("user-account-management"\)[\s\S]{0,240}set_focus/
);
const refreshFunction = composable.match(
  /async function refresh\(\)[\s\S]*?(?=\n  async function login)/
)?.[0];
assert.ok(refreshFunction, "useAgentAuth refresh function must exist");
assert.doesNotMatch(
  refreshFunction,
  /resetSession\(/,
  "a non-authoritative refresh error must not clear an authenticated session"
);

const types = await readFile(
  new URL("../src/types.ts", import.meta.url),
  "utf8"
);
assert.doesNotMatch(types, /AgentDeviceLogin|starting-device-login|device-authorizing/);

console.log("desktop login UI tests passed");
