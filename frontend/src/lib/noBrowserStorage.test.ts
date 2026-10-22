import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// SR-09: the project has no ESLint, so this test enforces "memory only" in CI (npm test).
// It scans every source file under src, except tests, for the browser storage APIs.
const SRC = fileURLToPath(new URL("..", import.meta.url));
const BANNED = /\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie/;

function sourceFiles(): string[] {
  return readdirSync(SRC, { recursive: true, encoding: "utf8" }).filter(
    (file) => /\.[jt]sx?$/.test(file) && !/\.test\.[jt]sx?$/.test(file),
  );
}

describe("SR-09: memory only", () => {
  it("SR-09: no source file uses localStorage, sessionStorage, indexedDB or document.cookie", () => {
    const files = sourceFiles();
    const hits = files.flatMap((file) =>
      readFileSync(join(SRC, file), "utf8")
        .split("\n")
        .flatMap((line, i) => (BANNED.test(line) ? [`${file}:${i + 1}: ${line.trim()}`] : [])),
    );

    // Guards against scanning the wrong folder and passing on nothing
    expect(files).toContain("App.tsx");
    expect(hits).toEqual([]);
  });
});
