import { describe, expect, it } from "vitest";

import { safeRedirectPath } from "@/auth/safeRedirect";

describe("safeRedirectPath", () => {
  it("keeps ordinary in-app paths", () => {
    expect(safeRedirectPath("/")).toBe("/");
    expect(safeRedirectPath("/analyze")).toBe("/analyze");
    expect(safeRedirectPath("/analyze/batch")).toBe("/analyze/batch");
    expect(safeRedirectPath("/reports/3f2b6c1e-1a2b-4c3d-8e9f-0a1b2c3d4e5f")).toBe(
      "/reports/3f2b6c1e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
    );
  });

  it.each([
    "//evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "/%2F/evil.example",
    "/%5Cevil.example",
    "https://evil.example",
    "javascript:alert(1)",
    "evil.example",
    "/\tevil",
    " /analyze",
    "",
  ])("rejects %j", (value) => {
    expect(safeRedirectPath(value)).toBe("/");
  });

  it("rejects non-string state", () => {
    expect(safeRedirectPath(undefined)).toBe("/");
    expect(safeRedirectPath(null)).toBe("/");
    expect(safeRedirectPath({ pathname: "//evil" })).toBe("/");
  });

  it("does not send the user back to the login page", () => {
    expect(safeRedirectPath("/login")).toBe("/");
  });
});
