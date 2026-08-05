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
assert.match(profileEditor, /return canvas\.toDataURL\('image\/png'\)/)
assert.doesNotMatch(profileEditor, /canvas\.toBlob/)
assert.match(profileEditor, /loadImage\(await readAsDataUrl\(file\)\)/)
assert.match(profileEditor, /reader\.readAsDataURL\(file\)/)
assert.doesNotMatch(profileEditor, /URL\.createObjectURL/)
assert.doesNotMatch(profileEditor, /URL\.revokeObjectURL/)
assert.match(profileEditor, /本地缩放为 64 × 64 像素并保存处理结果/)
assert.match(profileEditor, /avatarPreview\.value = await resizeAvatar\(file\)/)
assert.match(
  profileEditor,
  /avatarPreview\.value = await resizeAvatar\(file\)[\s\S]*?finally \{\s*input\.value = ''/,
)
assert.doesNotMatch(
  profileEditor,
  /const file = input\.files\?\.\[0\]\s*input\.value = ''/,
)
assert.doesNotMatch(profileEditor, /MAX_AVATAR_BYTES/)
assert.doesNotMatch(profileEditor, /file\.size/)
assert.doesNotMatch(profileEditor, /1 MiB/)
assert.doesNotMatch(profileEditor, /readImageDimensions/)
assert.doesNotMatch(profileEditor, /头像尺寸不能超过/)

console.log('Proxy Registry 头像 64 × 64 缩放回归检查通过')
