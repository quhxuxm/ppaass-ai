import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { readStyles } from "./read-styles.mjs";

const view = (
  await Promise.all([
    readFile(
      new URL("../src/views/PacketCaptureView.vue", import.meta.url),
      "utf8"
    ),
    readFile(
      new URL("../src/composables/usePacketCaptureView.ts", import.meta.url),
      "utf8"
    )
  ])
).join("\n");
const styles = await readStyles();
const workspace = await readFile(
  new URL("../src/AgentWorkspace.vue", import.meta.url),
  "utf8"
);

for (const label of [
  "数据包总数",
  "上传流量",
  "下载流量",
  "文件大小"
]) {
  assert.match(view, new RegExp(`>${label}<`));
}

assert.equal(
  view.match(/class="capture-metric-value"/g)?.length,
  4,
  "each capture metric should use the compact value row"
);
assert.match(view, /if \(bytes == null\)\s*\{\s*return "—"/);
assert.match(view, /if \(bytes < 1024\)/);
assert.match(view, /Math\.max\(0, Math\.round\(bytes\)\).*字节/);
assert.match(view, /state\.report\.total_packets === 0.*state\.report\.file_size > 0/s);
assert.match(view, /\? "仅文件头"\s*:\s*"磁盘占用"/);
assert.match(view, /class="panel span-12 capture-console"/);
assert.doesNotMatch(view, /capture-settings|明文抓包结果|输出设置/);
assert.match(view, /v-if="hasCapturedPackets" class="capture-filters"/);
assert.match(
  styles,
  /\.capture-page\s*\{[^}]*align-items:\s*start/
);
assert.match(
  styles,
  /\.capture-metrics\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)/
);
assert.match(styles, /\.capture-metric-value\s*\{[^}]*display:\s*flex/);
assert.match(
  styles,
  /\.capture-empty\s*\{[^}]*min-height:\s*128px/
);
assert.match(
  styles,
  /\.capture-table-wrap\s*\{[^}]*max-height:\s*min\(520px,\s*55vh\)/
);
assert.match(
  styles,
  /\.capture-table th\s*\{[^}]*background:\s*var\(--capture-table-header\)[^}]*color:\s*var\(--app-text-muted\)/s
);
assert.match(
  styles,
  /\.capture-table code\s*\{[^}]*color:\s*var\(--app-text-strong\)/
);
assert.match(
  styles,
  /html\.app-dark \.capture-page\s*\{[^}]*--capture-table-header:\s*#111a22/
);
assert.doesNotMatch(
  styles,
  /var\(--(?:text-primary|text-secondary|text-muted|surface-raised|border-subtle)/
);
assert.doesNotMatch(workspace, /capture-workspace/);

console.log("packet capture layout tests passed");
