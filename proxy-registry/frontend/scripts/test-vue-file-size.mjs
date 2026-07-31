import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const sourceRoot = fileURLToPath(new URL('../src', import.meta.url))
const oversizedFiles = readdirSync(sourceRoot, { recursive: true })
  .filter((path) => path.endsWith('.vue'))
  .map((path) => {
    const absolutePath = join(sourceRoot, path)
    const lines = readFileSync(absolutePath, 'utf8').split(/\r?\n/).length
    return {
      lines,
      path: relative(sourceRoot, absolutePath),
    }
  })
  .filter(({ lines }) => lines > 400)

assert.deepEqual(
  oversizedFiles,
  [],
  `以下 Vue 文件超过 400 行：\n${oversizedFiles
    .map(({ lines, path }) => `- ${path}: ${lines} 行`)
    .join('\n')}`,
)

console.log('Proxy Registry Vue 文件行数检查通过（每个文件不超过 400 行）')
