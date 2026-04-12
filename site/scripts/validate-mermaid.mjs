import { readdir, readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";

const source = await readFile(new URL("../src/diagrams.ts", import.meta.url), "utf8");
const siteDiagrams = [...source.matchAll(/export const \w+Diagram = `([\s\S]*?)`;/g)]
  .map((match, index) => ({
    name: `site architecture diagram ${index + 1}`,
    chart: match[1],
  }));

if (siteDiagrams.length === 0) {
  throw new Error("No Mermaid diagrams found in site/src/diagrams.ts");
}

const docsDir = new URL("../../docs/", import.meta.url);
const docsDiagrams = [];

for (const entry of await readdir(docsDir, { withFileTypes: true })) {
  if (!entry.isFile()) {
    continue;
  }

  if (entry.name.endsWith(".mmd")) {
    docsDiagrams.push({
      name: `docs/${entry.name}`,
      chart: await readFile(new URL(entry.name, docsDir), "utf8"),
    });
    continue;
  }

  if (entry.name.endsWith(".md")) {
    const markdown = await readFile(new URL(entry.name, docsDir), "utf8");
    for (const [index, match] of [...markdown.matchAll(/```mermaid\n([\s\S]*?)```/g)].entries()) {
      docsDiagrams.push({
        name: `docs/${entry.name} block ${index + 1}`,
        chart: match[1],
      });
    }
  }
}

const dom = new JSDOM("<!doctype html><html><body></body></html>");
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", {
  value: dom.window.navigator,
  configurable: true,
});

const { default: mermaid } = await import("mermaid");

mermaid.initialize({
  startOnLoad: false,
  securityLevel: "loose",
});

for (const diagram of [...siteDiagrams, ...docsDiagrams]) {
  await mermaid.parse(diagram.chart, { suppressErrors: false });
  console.log(`${diagram.name} ok`);
}
