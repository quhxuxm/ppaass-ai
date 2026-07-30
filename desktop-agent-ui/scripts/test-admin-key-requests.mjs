import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

async function source(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

const [
  app,
  workspace,
  sidebar,
  view,
  composable,
  types,
  rustPolling,
  rustHttp,
  bootstrap,
  styles
] = await Promise.all([
  source("src/App.vue"),
  source("src/AgentWorkspace.vue"),
  source("src/components/AppSidebar.vue"),
  source("src/views/AdminKeyRequestsView.vue"),
  source("src/composables/useAdminKeyRequests.ts"),
  source("src/types.ts"),
  source("src-tauri/src/app/admin_key_requests.rs"),
  source("src-tauri/src/auth/admin_key_requests.rs"),
  source("src-tauri/src/app/bootstrap.rs"),
  source("src/styles.css")
]);

assert.match(workspace, /tab\.key !== "admin-requests"/);
assert.match(workspace, /props\.account\.role === "admin"/);
assert.match(workspace, /props\.accountStatus === "active"/);
assert.match(workspace, /<AdminKeyRequestsView/);
assert.match(sidebar, /tab\.key === 'admin-requests'/);
assert.match(sidebar, /:badge=/);
assert.match(sidebar, /'nav-button-count-badge'/);
assert.match(sidebar, /'nav-button-count-badge-wide'/);
assert.match(sidebar, /:badge-class=/);
assert.match(sidebar, /'nav-request-badge-circle': adminRequestCount < 10/);
assert.match(sidebar, /'nav-request-badge-wide': adminRequestCount >= 10/);
assert.match(styles, /\.nav-button\.p-button \.nav-request-badge-circle\.p-badge/);
assert.match(styles, /width: 24px !important/);
assert.match(styles, /height: 24px !important/);
assert.match(styles, /border-radius: 50% !important/);
assert.match(styles, /\.nav-button\.p-button \.nav-request-badge-wide\.p-badge/);

for (const expected of [
  "request.request_message",
  "request.requested_at",
  "request.username",
  "<DatePicker",
  "<Checkbox",
  "approvalProxyAddressIds.value.length > 0",
  "rejectionRequest",
  "确认拒绝"
]) {
  assert.ok(view.includes(expected), `missing admin request UI: ${expected}`);
}
assert.match(view, /request\.proxy_address_ids\.filter/);
assert.match(view, /address\.enabled/);

assert.match(
  composable,
  /listen<AgentAdminKeyRequestUpdate>\(\s*"agent-admin-key-requests-updated"/
);
assert.match(composable, /new Set\(\s*next\.requests\.map/);
assert.match(composable, /!knownRequestIds\.has\(requestId\)/);
assert.match(composable, /refresh_agent_admin_key_requests/);
assert.match(composable, /approve_agent_admin_key_request_command/);
assert.match(composable, /reject_agent_admin_key_request_command/);
assert.match(composable, /dependencies\.account\.value\?\.role === "admin"/);
assert.match(composable, /dependencies\.accountStatus\.value === "active"/);

assert.match(app, /useAdminKeyRequests/);
assert.match(app, /adminRequests\.notice\.value/);
assert.match(app, /:admin-request-count|:admin-key-requests/);
assert.doesNotMatch(types, /agent_access_token|agentAccessToken/);
assert.doesNotMatch(composable, /bearer|authorization/i);
assert.doesNotMatch(view, /bearer|authorization|accessToken/i);

assert.match(
  rustPolling,
  /const ADMIN_KEY_REQUEST_POLL_SECONDS: u64 = 60/
);
assert.match(rustPolling, /replace_admin_key_request_inbox/);
assert.match(rustPolling, /notify_new_admin_requests\(app, new_ids\.len\(\)\)/);
assert.match(rustPolling, /收到 \{count\} 个新的待审批密钥申请/);
assert.doesNotMatch(
  rustPolling.match(/fn notify_new_admin_requests[\s\S]*?\\n\}/)?.[0] ?? "",
  /request_message|留言/
);
assert.match(rustHttp, /\.bearer_auth\(access_token\)/);
assert.match(rustHttp, /deny_unknown_fields/g);
assert.match(bootstrap, /tauri_plugin_notification::init\(\)/);
assert.match(bootstrap, /start_agent_admin_key_request_polling/);

console.log("desktop admin key request tests passed");
