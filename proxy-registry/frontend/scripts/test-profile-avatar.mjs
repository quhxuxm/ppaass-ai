import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const profileEditor = await readFile(
  new URL('../src/components/ProfileEditor.vue', import.meta.url),
  'utf8',
)

assert.match(profileEditor, /const AVATAR_SIZE = 64/)
assert.match(profileEditor, /canvas\.width = AVATAR_SIZE/)
assert.match(profileEditor, /canvas\.height = AVATAR_SIZE/)
assert.match(
  profileEditor,
  /context\.drawImage\(image, 0, 0, AVATAR_SIZE, AVATAR_SIZE\)/,
)
assert.match(profileEditor, /canvas\.toBlob\([\s\S]*?'image\/png'/)
assert.match(profileEditor, /本地缩放为 64 × 64 像素并保存处理结果/)
assert.match(profileEditor, /avatarPreview\.value = await resizeAvatar\(file\)/)
assert.doesNotMatch(profileEditor, /MAX_AVATAR_BYTES/)
assert.doesNotMatch(profileEditor, /file\.size/)
assert.doesNotMatch(profileEditor, /1 MiB/)
assert.doesNotMatch(profileEditor, /readImageDimensions/)
assert.doesNotMatch(profileEditor, /头像尺寸不能超过/)

console.log('Proxy Registry 头像 64 × 64 缩放回归检查通过')
