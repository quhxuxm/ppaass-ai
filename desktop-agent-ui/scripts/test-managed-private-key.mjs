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
  assert.match(egressView, /class="panel span-5 egress-endpoints-panel"/);
  assert.match(egressView, /class="panel span-7 egress-transport-panel"/);
  assert.match(egressView, /summary\.transport_mode === 'tcp' \? 'span-12' : 'span-5'/);
  assert.match(egressView, /class="panel span-7 egress-native-udp-panel"/);
  assert.match(egressView, /class="panel span-12 egress-yamux-panel"/);

  const workspace = await readFile(new URL("../src/AgentWorkspace.vue", import.meta.url), "utf8");
  assert.doesNotMatch(workspace, /selectPrivateKey|select-private-key/);
  assert.match(workspace, /<AppSidebar[\s\S]*:account-username="account\.username"[\s\S]*@logout="emit\('logout'\)"/);
  assert.doesNotMatch(workspace, /<AppTopbar[\s\S]*:account-username=/);

  const sidebar = await readFile(new URL("../src/components/AppSidebar.vue", import.meta.url), "utf8");
  assert.match(sidebar, /class="sidebar-account"/);
  assert.match(sidebar, /<small>当前账户<\/small>/);
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
  assert.match(loginView, /label="新用户注册"/);
  assert.match(loginView, /@click="emit\('register'\)"/);
  assert.match(loginView, /loadRememberedAgentLogin/);

  const appSource = await readFile(new URL("../src/App.vue", import.meta.url), "utf8");
  assert.doesNotMatch(appSource, /default-proxy-web-url|default_proxy_web_url/);

  const authComposable = await readFile(
    new URL("../src/composables/useAgentAuth.ts", import.meta.url),
    "utf8"
  );
  assert.doesNotMatch(
    authComposable,
    /LOCAL_PROXY_WEB_URL|proxyWebUrl|proxy_web_url|default_proxy_web_url|127\.0\.0\.1:8787/
  );
  assert.match(authComposable, /invoke\("open_user_registration"\)/);
  assert.doesNotMatch(styles, /\.auth-server-settings/);
  assert.match(styles, /\.auth-login-options\s*\{/);

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
