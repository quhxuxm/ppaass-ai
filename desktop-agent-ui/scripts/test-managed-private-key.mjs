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
  if (!String(args[0]).includes("called when there is no active component instance")) {
    originalWarn(...args);
  }
};

try {
  const egressView = await readFile(new URL("../src/views/EgressView.vue", import.meta.url), "utf8");
  assert.doesNotMatch(egressView, /summary\.private_key_path/);
  assert.doesNotMatch(egressView, /select-private-key|选择私钥文件/);
  assert.doesNotMatch(egressView, /@update:model-value=.*username/);
  assert.doesNotMatch(egressView, /身份凭据|managed-credential-status/);
  assert.doesNotMatch(egressView, /凭据已由 Proxy Web 托管|Agent 不展示或接受手工更改/);
  assert.match(egressView, /class="content-grid egress-grid"/);
  assert.doesNotMatch(egressView, /egress-endpoints-panel|proxy_addrs|远端出口地址/);
  assert.match(egressView, /class="panel span-12 egress-transport-panel"/);
  assert.match(egressView, /summary\.transport_mode === 'tcp' \? 'span-12' : 'span-5'/);
  assert.match(egressView, /class="panel span-7 egress-native-udp-panel"/);
  assert.match(egressView, /class="panel span-12 egress-yamux-panel"/);

  const workspace = await readFile(new URL("../src/AgentWorkspace.vue", import.meta.url), "utf8");
  assert.doesNotMatch(workspace, /selectPrivateKey|select-private-key/);
  assert.match(workspace, /<AppSidebar[\s\S]*:account-username="account\.username"[\s\S]*@logout="emit\('logout'\)"/);
  assert.doesNotMatch(workspace, /<AppTopbar[\s\S]*:account-username=/);

  const sidebar = await readFile(new URL("../src/components/AppSidebar.vue", import.meta.url), "utf8");
  assert.match(sidebar, /class="sidebar-account"/);
  assert.match(sidebar, /accountRole === "admin" \? "管理员" : "普通用户"/);
  assert.match(sidebar, /accountRole === 'admin' \? '管理用户' : '账户管理'/);
  assert.match(sidebar, /label="生成新密钥"/);
  assert.match(sidebar, /v-if="canRotateKey"/);
  assert.match(sidebar, /class="sidebar-logout"/);

  const topbar = await readFile(new URL("../src/components/AppTopbar.vue", import.meta.url), "utf8");
  assert.doesNotMatch(topbar, /topbar-account|accountUsername|logoutBusy|emit\('logout'\)/);

  const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
  assert.match(
    styles,
    /\.sidebar-account\s*\{[\s\S]*?width:\s*100%;[\s\S]*?min-width:\s*0;[\s\S]*?max-width:\s*100%;/
  );
  assert.match(
    styles,
    /\.sidebar-account-copy > strong\s*\{[\s\S]*?max-width:\s*100%;[\s\S]*?text-overflow:\s*ellipsis;[\s\S]*?white-space:\s*nowrap;/
  );

  const composableSource = await readFile(
    new URL("../src/composables/useDesktopAgent.ts", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(composableSource, /plugin-dialog|openFileDialog|selectPrivateKey/);

  const typesSource = await readFile(new URL("../src/types.ts", import.meta.url), "utf8");
  assert.doesNotMatch(typesSource, /\bprivate_key_path\s*:/);
  assert.doesNotMatch(typesSource, /proxy_web_url|default_proxy_web_url|proxyWebUrl/);

  const loginView = await readFile(new URL("../src/views/LoginView.vue", import.meta.url), "utf8");
  assert.doesNotMatch(
    loginView,
    /defaultProxyWebUrl|proxyWebUrl|agent-login-proxy-web-url|Proxy Web 地址|连接设置|auth-server-settings/
  );
  assert.match(loginView, /import Checkbox from "primevue\/checkbox"/);
  assert.match(loginView, /记住用户名和密码/);
  assert.match(loginView, /label="注册和账户管理"/);
  assert.match(loginView, /@click="emit\('manageAccount'\)"/);
  assert.match(loginView, /loadRememberedAgentLogin/);

  const appSource = await readFile(new URL("../src/App.vue", import.meta.url), "utf8");
  assert.doesNotMatch(appSource, /default-proxy-web-url|default_proxy_web_url/);
  const tauriAppStateSource = await readFile(
    new URL("../src-tauri/src/app/state.rs", import.meta.url),
    "utf8"
  );
  const statusReporter = tauriAppStateSource.slice(
    tauriAppStateSource.indexOf("fn report_verified_proxy_auth_status"),
    tauriAppStateSource.indexOf("fn current_ui_config_path")
  );
  assert.match(statusReporter, /保留登录状态和本机凭据/);
  assert.doesNotMatch(
    statusReporter,
    /stop_agent_inner_command|take_authenticated_session|destroy_managed|destroy_persisted/
  );

  const authComposable = await readFile(
    new URL("../src/composables/useAgentAuth.ts", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(
    authComposable,
    /LOCAL_PROXY_WEB_URL|proxyWebUrl|proxy_web_url|default_proxy_web_url|127\.0\.0\.1:8787/
  );
  assert.match(authComposable, /invoke\("open_user_account_management"\)/);
  assert.match(authComposable, /invoke<AgentAuthState>\("rotate_agent_key"/);
  assert.match(authComposable, /invoke<AgentAuthState>\("get_agent_auth_state"\)/);
  assert.doesNotMatch(authComposable, /localStorage|saveRememberedAgentLogin/);
  assert.match(authComposable, /listen<string>\("agent-auth-status"/);
  assert.match(authComposable, /event\.payload === "user_disabled"/);
  assert.match(authComposable, /登录状态和本机凭据已保留/);
  assert.doesNotMatch(authComposable, /account\.value\?\.expires_at[\s\S]{0,120}(?:setTimeout|logout)/);
  assert.doesNotMatch(styles, /\.auth-server-settings/);
  assert.match(styles, /\.auth-login-options\s*\{/);

  const rotateDialog = await readFile(
    new URL("../src/components/RotateKeyDialog.vue", import.meta.url),
    "utf8"
  );
  assert.match(rotateDialog, /label="确认生成并应用"/);
  assert.match(rotateDialog, /input-id="rotate-key-password"/);
  assert.match(rotateDialog, /私钥不会显示/);
  assert.doesNotMatch(rotateDialog, /private_key_pem|proxyWebUrl|proxy_web_url/);

  assert.match(appSource, /loadRememberedAgentLogin/);
  assert.match(appSource, /remembered\?\.username\.trim\(\) === account\.value\?\.username/);
  assert.match(appSource, /account\.key_version/);
  assert.match(appSource, /account\.role/);
  assert.match(appSource, /\.\.\.account\.permissions/);

  const loginCommands = await readFile(
    new URL("../src-tauri/src/app/login_commands.rs", import.meta.url),
    "utf8"
  );
  const rotateCommand = loginCommands.match(
    /pub\(crate\) async fn rotate_agent_key[\s\S]*?(?=\n#\[tauri::command\])/
  )?.[0];
  assert.ok(rotateCommand, "rotate_agent_key command must exist");
  assert.match(rotateCommand, /let was_running = get_agent_state_inner\(&runtime\)\?\.running/);
  assert.match(rotateCommand, /provision_downloaded_credential/);
  assert.match(rotateCommand, /if was_running[\s\S]*start_agent_command/);
  assert.match(rotateCommand, /新密钥已应用，但 Agent 自动重启失败/);

  const rememberedLoginSource = await readFile(
    new URL("../src/rememberedLogin.ts", import.meta.url),
    "utf8"
  );
  assert.match(rememberedLoginSource, /localStorage\.getItem\(REMEMBERED_AGENT_LOGIN_KEY\)/);
  assert.match(rememberedLoginSource, /localStorage\.setItem\(REMEMBERED_AGENT_LOGIN_KEY/);
  assert.match(rememberedLoginSource, /localStorage\.removeItem\(REMEMBERED_AGENT_LOGIN_KEY\)/);

  const configTomlSource = await readFile(
    new URL("../src/configToml.ts", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(
    configTomlSource,
    /config\/local\/agent\.toml\?raw|127\.0\.0\.1:8787/
  );

  const packageSource = await readFile(new URL("../package.json", import.meta.url), "utf8");
  assert.doesNotMatch(packageSource, /@tauri-apps\/plugin-dialog/);
  const cargoSource = await readFile(new URL("../src-tauri/Cargo.toml", import.meta.url), "utf8");
  assert.doesNotMatch(cargoSource, /tauri-plugin-dialog/);
  assert.doesNotMatch(cargoSource, /\bkeyring\s*=/);
  const capabilitySource = await readFile(
    new URL("../src-tauri/capabilities/default.json", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(capabilitySource, /dialog:allow-open/);
  const tauriConfig = JSON.parse(
    await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8")
  );
  assert.equal(
    tauriConfig.bundle.resources["../../config/remote/agent.toml"],
    "config/remote/agent.toml"
  );
  assert.equal(
    tauriConfig.bundle.resources["../../config/local/agent.toml"],
    "config/local/agent.toml"
  );
  assert.equal(tauriConfig.bundle.resources["../../keys/user1.pem"], undefined);
  assert.equal(tauriConfig.bundle.resources["../../keys/user2.pem"], undefined);
  const packagedAgentConfig = await readFile(
    new URL("../../config/remote/agent.toml", import.meta.url),
    "utf8"
  );
  assert.match(packagedAgentConfig, /^proxy_web_url = "https:\/\/140\.82\.30\.214"$/m);
  assert.doesNotMatch(packagedAgentConfig, /proxy_web_url = "http:\/\/127\.0\.0\.1:8787"/);
  assert.doesNotMatch(packagedAgentConfig, /^\s*username\s*=/m);
  assert.doesNotMatch(packagedAgentConfig, /^\s*private_key_path\s*=/m);
  assert.doesNotMatch(packagedAgentConfig, /^\s*proxy_addrs\s*=/m);

  const {
    fallbackRawConfig,
    redactManagedIdentityFromToml,
    summarizeRaw
  } = await server.ssrLoadModule("/src/configToml.ts");
  const { useDesktopAgent } = await server.ssrLoadModule("/src/composables/useDesktopAgent.ts");

  assert.doesNotMatch(fallbackRawConfig, /\busername\s*=/);
  assert.doesNotMatch(fallbackRawConfig, /\bprivate_key_path\s*=/);
  assert.doesNotMatch(fallbackRawConfig, /\bproxy_web_url\s*=/);

  const redacted = redactManagedIdentityFromToml([
    'username = "attacker"',
    '"private_key_path" = "/tmp/attacker.pem"',
    "'proxy_web_url' = \"https://hidden.example.com\"",
    "transport_mode = \"tcp\"",
    ""
  ].join("\n"));
  assert.doesNotMatch(redacted, /attacker|private_key_path|username|proxy_web_url|hidden\.example\.com/);
  assert.match(redacted, /^transport_mode = "tcp"$/m);

  const desktopAgent = useDesktopAgent();
  desktopAgent.state.config = {
    path: "/tmp/agent.toml",
    raw: 'transport_mode = "udp"\n',
    summary: summarizeRaw('transport_mode = "udp"\n')
  };
  desktopAgent.setRawConfig([
    'username = "attacker"',
    'private_key_path = "/tmp/attacker.pem"',
    'proxy_web_url = "https://hidden.example.com"',
    'transport_mode = "tcp"',
    ""
  ].join("\n"));
  assert.doesNotMatch(
    desktopAgent.state.config.raw,
    /attacker|private_key_path|username|proxy_web_url|hidden\.example\.com/
  );
  assert.equal(desktopAgent.state.config.summary.transport_mode, "tcp");
  assert.equal(desktopAgent.state.dirty, true);
} finally {
  console.warn = originalWarn;
  await server.close();
}

console.log("managedPrivateKey tests passed");
