import { copyFile, mkdir, readdir, writeFile } from "node:fs/promises";

const docsDir = new URL("../../docs/", import.meta.url);
const outDir = new URL("../../build/", import.meta.url);

await mkdir(outDir, { recursive: true });

for (const entry of await readdir(docsDir, { withFileTypes: true })) {
  if (entry.isFile() && entry.name.endsWith(".md")) {
    await copyFile(new URL(entry.name, docsDir), new URL(entry.name, outDir));
  }
}

await writeFile(new URL(".nojekyll", outDir), "");
