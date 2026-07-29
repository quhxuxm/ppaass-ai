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

console.log('Proxy Web 管理员用户列表与编辑弹窗布局回归检查通过')
