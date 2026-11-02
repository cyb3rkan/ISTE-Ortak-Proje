/// <reference types="node" />
// Node typings are scoped to this file: it runs in the `node` environment and
// reads the source tree. (Vitest 4 no longer pulls them in transitively, and
// they must not leak into the browser app's global types.)
/**
 * Static-source security regression checks.
 *
 * These walk the actual `src/` tree and assert that banned patterns never
 * appear. They are cheap insurance: a future edit that introduces
 * `dangerouslySetInnerHTML` or a hard-coded API key fails CI immediately.
 *
 * @vitest-environment node
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// In the node environment `import.meta.url` is a real file:// URL.
const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

function collectSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...collectSourceFiles(full));
    } else if (/\.(ts|tsx)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

const SOURCE_FILES = collectSourceFiles(SRC_DIR);

function readAll(): Array<{ file: string; text: string }> {
  return SOURCE_FILES.map((file) => ({
    file,
    text: readFileSync(file, "utf-8"),
  }));
}

describe("security regression — source scan", () => {
  it("finds source files to scan", () => {
    expect(SOURCE_FILES.length).toBeGreaterThan(10);
  });

  it("never uses dangerouslySetInnerHTML as a JSX prop", () => {
    // Match real usage (`dangerouslySetInnerHTML={` or `:`), not a mention of
    // the word in a comment explaining why we don't use it.
    const offenders = readAll()
      .filter((f) => /dangerouslySetInnerHTML\s*[:=]/.test(f.text))
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never references a VITE_API_KEY env var", () => {
    const offenders = readAll()
      .filter((f) => f.text.includes("VITE_API_KEY"))
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never references a VITE_ADMIN_API_KEY env var", () => {
    const offenders = readAll()
      .filter((f) => f.text.includes("VITE_ADMIN_API_KEY"))
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never sends an X-API-Key header", () => {
    const offenders = readAll()
      .filter((f) => f.text.includes("X-API-Key"))
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never sends an X-Admin-API-Key header", () => {
    const offenders = readAll()
      .filter((f) => f.text.includes("X-Admin-API-Key"))
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("every target=_blank link is paired with rel=noopener noreferrer", () => {
    const offenders = readAll()
      .filter(
        (f) =>
          f.text.includes('target="_blank"') &&
          !f.text.includes('rel="noopener noreferrer"'),
      )
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never persists an auth token to localStorage", () => {
    // Catches `localStorage.setItem("token", ...)` and friends. The access
    // token must live in memory only.
    const offenders = readAll()
      .filter((f) =>
        /localStorage\s*\.\s*setItem\s*\(\s*["'`][^"'`]*(token|auth|jwt)/i.test(
          f.text,
        ),
      )
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never persists an auth token to sessionStorage", () => {
    const offenders = readAll()
      .filter((f) =>
        /sessionStorage\s*\.\s*setItem\s*\(\s*["'`][^"'`]*(token|auth|jwt)/i.test(
          f.text,
        ),
      )
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });

  it("never references a VITE_ADMIN_API_KEY or VITE_API_KEY (re-check)", () => {
    const offenders = readAll()
      .filter(
        (f) =>
          f.text.includes("VITE_API_KEY") ||
          f.text.includes("VITE_ADMIN_API_KEY"),
      )
      .map((f) => f.file);
    expect(offenders).toEqual([]);
  });
});
