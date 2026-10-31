import { describe, expect, it } from "vitest";

import { prettyJson, summaryEntries, toDisplayString } from "@/lib/safeRender";

describe("safeRender", () => {
  it("keeps a <script> payload as an inert string", () => {
    const payload = "<script>alert(1)</script>";
    const out = toDisplayString(payload);
    // The function returns the string unchanged — it does NOT produce HTML.
    expect(out).toBe(payload);
    expect(typeof out).toBe("string");
  });

  it("stringifies objects rather than exposing them as markup", () => {
    const out = toDisplayString({ a: 1, evil: "<img src=x onerror=alert(1)>" });
    expect(typeof out).toBe("string");
    expect(out).toContain("\"a\":1");
  });

  it("returns empty string for null/undefined", () => {
    expect(toDisplayString(null)).toBe("");
    expect(toDisplayString(undefined)).toBe("");
  });

  it("truncates very long strings", () => {
    const out = toDisplayString("x".repeat(10_000));
    expect(out.length).toBeLessThanOrEqual(4000);
    expect(out.endsWith("…")).toBe(true);
  });

  it("summaryEntries flattens a record into key/value string pairs", () => {
    const entries = summaryEntries({
      malicious: 5,
      note: "<b>not html</b>",
    });
    expect(entries).toEqual([
      { key: "malicious", value: "5" },
      { key: "note", value: "<b>not html</b>" },
    ]);
  });

  it("summaryEntries returns [] for non-objects", () => {
    expect(summaryEntries(null)).toEqual([]);
    expect(summaryEntries(undefined)).toEqual([]);
  });

  it("prettyJson formats nested data", () => {
    const out = prettyJson({ x: { y: 1 } });
    expect(out).toContain("\n");
    expect(out).toContain("\"y\": 1");
  });
});
