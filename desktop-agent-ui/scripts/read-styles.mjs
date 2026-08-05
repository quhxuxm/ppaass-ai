import { readdir, readFile } from "node:fs/promises";

const sourceRoot = new URL("../src/", import.meta.url);
const stylesRoot = new URL("../src/styles/", import.meta.url);

export async function readStyles() {
  const stylePaths = (await readdir(stylesRoot, { recursive: true }))
    .filter((path) => path.endsWith(".css"))
    .sort();
  return (
    await Promise.all([
      readFile(new URL("styles.css", sourceRoot), "utf8"),
      ...stylePaths.map((path) => readFile(new URL(path, stylesRoot), "utf8"))
    ])
  ).join("\n");
}
