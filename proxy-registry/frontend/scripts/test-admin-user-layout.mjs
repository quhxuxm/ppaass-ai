import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const styles = readFileSync(
  new URL('../src/styles.css', import.meta.url),
  'utf8',
)
const editorStyles = readFileSync(
  new URL('../src/styles/user-editor.css', import.meta.url),
  'utf8',
)
const sessionTypes = readFileSync(
  new URL('../src/api/types.ts', import.meta.url),
  'utf8',
)
const sessionDecoder = readFileSync(
  new URL('../src/api/decoders/session.ts', import.meta.url),
  'utf8',
)

assert.match(app, /table-style="min-width: 72rem"/)
assert.doesNotMatch(app, /header="代理 \/ 密钥"/)
assert.doesNotMatch(app, /<Column header="密钥"/)
assert.match(app, /<Column header="密钥有效期" style="min-width: 9\.5rem">/)
assert.match(
  app,
  /class="key-expiry-value"[\s\S]*?:class="\{ expired: data\.keyState === 'expired' \}"/,
)
assert.match(
  styles,
  /\.key-expiry-value\.expired\s*\{[^}]*color:\s*#d92d20;[^}]*font-weight:\s*700;/s,
)
assert.match(app, /<Column header="角色" style="min-width: 7rem">/)
assert.doesNotMatch(app, /<Column header="角色 \/ 来源"/)
assert.doesNotMatch(
  app,
  /<small>\{\{ originLabel\(data\.profile\?\.origin\) \}\}<\/small>/,
)
assert.match(app, /<Column header="状态" style="min-width: 5rem">/)
assert.doesNotMatch(app, /<Column header="Web 账号"/)
assert.match(
  app,
  /class="account-status-indicator"[\s\S]*?:class="\{ active: data\.account\?\.status === 'active' \}"[\s\S]*?:title="accountStatusLabel\(data\)"/,
)
assert.match(
  styles,
  /\.account-status-indicator\s*\{[^}]*border-radius:\s*50%;[^}]*background:\s*#98a2b3;/s,
)
assert.match(
  styles,
  /\.account-status-indicator\.active\s*\{[^}]*background:\s*#12b76a;/s,
)
assert.match(
  app,
  /<strong :title="managedUsername\(data\)">\s*\{\{ managedUsername\(data\) \}\}\s*<\/strong>/,
)
assert.doesNotMatch(
  app,
  /<small>\{\{ data\.account\?\.email \|\| originLabel\(data\.profile\?\.origin\) \}\}<\/small>/,
)

assert.match(app, /header="Agent 权限" style="min-width: 18rem"/)
assert.match(
  app,
  /v-for="permission in managedAgentPermissions\(data\)\.slice\(0, 2\)"/,
)
assert.doesNotMatch(app, /profile\.permissions\.slice\(/)
assert.match(app, /managedHiddenPermissionCount\(data\)/)
assert.match(app, /data\.proxyAddresses\.slice\(0, 1\)/)
assert.match(app, /managedProxyAddressesTitle\(data\)/)
assert.match(
  styles,
  /\.user-permission-tags\s*\{[^}]*flex-wrap:\s*nowrap;[^}]*overflow:\s*hidden;/s,
)
assert.match(
  styles,
  /\.user-list-tag-summary \.p-tag-label\s*\{[^}]*text-overflow:\s*ellipsis;[^}]*white-space:\s*nowrap;/s,
)
assert.match(
  styles,
  /@media \(max-width: 1360px\)\s*\{[\s\S]*?\.p-datatable-frozen-column:last-child\s*\{[^}]*position:\s*static\s*!important;/,
)

assert.match(
  app,
  /<\/label>\s*<small>关闭后停止 Agent 代理，Web 账户仍可登录。<\/small>/,
)
assert.match(
  editorStyles,
  /\.user-editor-runtime-grid \.p-datepicker\s*\{[^}]*height:\s*42px;[^}]*min-height:\s*42px;/s,
)
assert.match(
  editorStyles,
  /\.proxy-toggle-card\s*\{[^}]*height:\s*42px;[^}]*min-height:\s*42px;[^}]*padding:\s*0 10px;/s,
)
assert.doesNotMatch(
  editorStyles,
  /\.proxy-toggle-card\s*\{[^}]*min-height:\s*40px;/s,
)
assert.doesNotMatch(
  app,
  /:value="`\$\{(?:create|edit)Form\.agentPermissions\.length\} \/ \$\{agentPermissionOptions\.length\}`"/,
)
assert.doesNotMatch(
  app,
  /grantedAgentPermissions\.length\} \/ \$\{agentPermissionOptions\.length\}/,
)
assert.match(sessionTypes, /agentHandoff: boolean/)
assert.match(sessionTypes, /registryInstanceId: string/)
assert.match(
  sessionDecoder,
  /boolValue\(source\.agent_handoff\)[\s\S]*?stringValue\(source\.registry_instance_id\)[\s\S]*?return \{ registryInstanceId, authenticated, account, agentHandoff \}/,
)
assert.match(
  app,
  /const isAgentHandoffSession = computed\([\s\S]*?session\.value\?\.agentHandoff === true/,
)
assert.match(
  app,
  /agentHandoff: session\.value\?\.agentHandoff \?\? false/,
)
assert.match(
  app,
  /Registry：\$\{session\?\.registryInstanceId \|\| 'unknown'\}/,
)
assert.match(
  app,
  /'topbar-logout-action',[\s\S]*?'agent-handoff-logout': isAgentHandoffSession[\s\S]*?label="退出登录"[\s\S]*?aria-label="退出登录"/,
)
assert.doesNotMatch(app, /class="mobile-logout-action"/)
assert.match(
  styles,
  /\.topbar-logout-action\.agent-handoff-logout\s*\{[^}]*display:\s*none;/s,
)
assert.match(
  styles,
  /@media \(max-width: 820px\)\s*\{[\s\S]*?\.topbar\s*\{[^}]*position:\s*sticky;[^}]*grid-template-columns:\s*minmax\(0, 1fr\) auto;[^}]*width:\s*100%;[\s\S]*?\.main-nav\s*\{[^}]*position:\s*static;[^}]*grid-column:\s*1 \/ -1;[^}]*grid-row:\s*2;[^}]*width:\s*100%;[\s\S]*?\.topbar-logout-action,\s*\.topbar-logout-action\.agent-handoff-logout\s*\{[^}]*display:\s*inline-flex;[^}]*min-width:\s*104px;[^}]*min-height:\s*40px;/s,
)
assert.match(
  styles,
  /@media \(max-width: 820px\)\s*\{[\s\S]*?\.topbar-logout-action \.p-button-label\s*\{[^}]*display:\s*inline;/s,
)
assert.match(
  styles,
  /@media \(max-width: 560px\)\s*\{[\s\S]*?\.brand\.compact > span:last-child\s*\{[^}]*display:\s*none;[\s\S]*?\.topbar-logout-action,\s*\.topbar-logout-action\.agent-handoff-logout\s*\{[^}]*width:\s*40px;[^}]*min-width:\s*40px;[\s\S]*?\.topbar-logout-action \.p-button-label\s*\{[^}]*display:\s*none;/s,
)
assert.match(
  app,
  /const displayedEditAgentPermissions = computed\(\{[\s\S]*?editForm\.role === 'admin'[\s\S]*?allAgentPermissionCodes/,
)
assert.match(
  app,
  /<section\s+v-if="\s*editingUser\?\.account &&\s*\(editingUser\.profile \|\| editForm\.role === 'admin'\)\s*"[\s\S]*?id="edit-agent-permissions-title">Agent 权限/,
)
assert.match(
  app,
  /管理员自动拥有以下全部权限，不能单独取消。/,
)
assert.match(
  app,
  /v-model="displayedEditAgentPermissions"[\s\S]*?:disabled="\s*editForm\.role === 'admin'/,
)
assert.doesNotMatch(
  app,
  /v-if="editingUser\.account && editForm\.role === 'admin'"\s+value="Agent 全权限"/,
)
assert.match(
  styles,
  /\.topbar\s*\{[^}]*grid-template-columns:\s*auto minmax\(0, 1fr\) auto;[^}]*gap:\s*clamp\(20px, 3vw, 42px\);/s,
)
assert.match(
  styles,
  /\.main-nav\s*\{[^}]*justify-self:\s*start;[^}]*border-radius:\s*12px;[^}]*background:\s*#f8fafc;/s,
)
assert.match(
  styles,
  /\.main-nav button\.active\s*\{[^}]*background:\s*#fff;[^}]*box-shadow:/s,
)

console.log('Proxy Registry 管理员用户列表与编辑弹窗布局回归检查通过')
