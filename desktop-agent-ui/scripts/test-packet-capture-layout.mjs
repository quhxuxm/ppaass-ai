import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const view = await readFile(
  new URL("../src/views/PacketCaptureView.vue", import.meta.url),
  "utf8"
);
const styles = await readFile(
  new URL("../src/styles.css", import.meta.url),
  "utf8"
);

for (const label of [
  "数据包总数",
  "上传流量",
  "下载流量",
  "PCAP 文件大小"
]) {
  assert.match(view, new RegExp(`>${label}<`));
}

assert.equal(
  view.match(/class="capture-metric-value"/g)?.length,
  4,
  "each capture metric should use the compact value row"
);
assert.match(view, /if \(bytes == null\)\s*\{\s*return "—"/);
assert.match(view, /return bytes > 0 \? formatBytes\(bytes\) : "0 字节"/);
assert.match(
  styles,
  /\.capture-page\s*\{[^}]*grid-template-rows:\s*auto auto minmax\(280px,\s*1fr\)/
);
assert.match(
  styles,
  /\.capture-metrics \.metric-tile\s*\{[^}]*min-height:\s*68px/
);
assert.match(styles, /\.capture-metric-value\s*\{[^}]*display:\s*flex/);

console.log("packet capture layout tests passed");
