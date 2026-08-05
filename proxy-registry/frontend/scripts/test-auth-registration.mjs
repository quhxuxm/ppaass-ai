import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const authPage = await readFile(
  new URL('../src/components/app/AuthPage.vue', import.meta.url),
  'utf8',
)
const authActions = await readFile(
  new URL('../src/controller/actions/authAgent.ts', import.meta.url),
  'utf8',
)
const state = await readFile(
  new URL('../src/controller/state.ts', import.meta.url),
  'utf8',
)

assert.match(state, /authForm = reactive\([\s\S]*?confirmPassword: ''/)
assert.match(authPage, /v-if="authMode === 'register'"/)
assert.match(authPage, /for="auth-confirm-password">确认密码/)
assert.match(authPage, /v-model="authForm\.confirmPassword"/)
assert.match(authPage, /input-id="auth-confirm-password"/)
assert.match(authPage, /autocomplete: 'new-password'/)
assert.match(
  authActions,
  /authMode\.value === 'register' && !authForm\.confirmPassword/,
)
assert.match(
  authActions,
  /authForm\.password !== authForm\.confirmPassword/,
)
assert.match(authActions, /两次输入的密码不一致/)
assert.match(authActions, /authForm\.confirmPassword = ''/)

console.log('Proxy Registry 注册密码二次确认回归检查通过')
