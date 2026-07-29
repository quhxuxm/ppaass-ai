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

assert.match(app, /table-style="min-width: 80\.5rem"/)
assert.match(app, /header="代理 \/ 密钥"/)
assert.doesNotMatch(app, /<Column header="密钥"/)

assert.match(app, /header="Agent 权限" style="min-width: 18rem"/)
assert.match(app, /v-for="permission in managedAgentPermissions\(data\)"/)
assert.doesNotMatch(app, /profile\.permissions\.slice\(/)
assert.match(app, /附加权限 \$\{managedCustomPermissions\(data\)\.length\} 项/)
assert.match(
  styles,
  /\.user-permission-tags\s*\{[^}]*flex-wrap:\s*wrap;/s,
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
  /\.user-editor-runtime-grid \.p-datepicker\s*\{[^}]*min-height:\s*42px;/s,
)
assert.match(
  editorStyles,
  /\.proxy-toggle-card\s*\{[^}]*min-height:\s*42px;/s,
)
assert.doesNotMatch(
  editorStyles,
  /\.proxy-toggle-card\s*\{[^}]*min-height:\s*40px;/s,
)

console.log('Proxy Web 管理员用户列表与编辑弹窗布局回归检查通过')
