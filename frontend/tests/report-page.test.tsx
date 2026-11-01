import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  downloadTextFile,
  extensionForFormat,
  safeFilename,
} from "@/lib/download";
import { ReportPage } from "@/pages/ReportPage";
import { MemoryRouter, Route, Routes } from "react-router";
import type { ReactNode } from "react";

import type { AuthContextValue } from "@/auth/authTypes";
import { AuthContext } from "@/auth/useAuth";

const REPORT_ID = "11111111-1111-4111-8111-111111111111";

function AuthAs({ role, children }: { role: string | null; children: ReactNode }) {
  const value: AuthContextValue = {
    status: role ? "authenticated" : "anonymous",
    user: role ? { username: "tester", role } : null,
    login: async () => undefined,
    logout: async () => undefined,
    getAccessToken: () => null,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function reportResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const ENRICHMENT_CONTENT = {
  ioc: "185.220.101.1",
  ioc_type: "ipv4",
  risk: {
    score: 44,
    level: "MEDIUM",
    reasons: ["AbuseIPDB: 100% abuse confidence, 409 reports."],
    detection_confidence: 0.65,
    evidence_status: "partial",
    provider_coverage: { queried: 2, responded: 1, failed: 1, not_found: 0 },
    unavailable_providers: ["Shodan"],
  },
  providers: [
    { name: "AbuseIPDB", status: "success", data_summary: { abuse_confidence_score: 100, total_reports: 409 } },
    { name: "Shodan", status: "error", data_summary: {}, error: "HTTP 403" },
  ],
  mitre: [{ tactic: "Command and Control", technique_id: "T1090", technique_name: "Proxy", basis: "contextual" }],
  ai_analysis: null,
  meta: { timestamp: "2026-10-30T10:00:00+00:00", from_cache: false },
};

describe("download helpers", () => {
  it("produces a safe filename", () => {
    expect(safeFilename("report-../../etc/passwd", "json")).not.toContain("/");
    expect(safeFilename("report-abc", "md")).toBe("report-abc.md");
  });

  it("maps formats to extensions", () => {
    expect(extensionForFormat("json")).toBe("json");
    expect(extensionForFormat("markdown")).toBe("md");
    expect(extensionForFormat("weird")).toBe("txt");
  });

  it("creates a Blob object URL on download", () => {
    const createSpy = vi
      .spyOn(URL, "createObjectURL")
      .mockReturnValue("blob:fake");
    const revokeSpy = vi
      .spyOn(URL, "revokeObjectURL")
      .mockImplementation(() => undefined);

    downloadTextFile("report.txt", "hello");

    expect(createSpy).toHaveBeenCalledTimes(1);
    const blobArg = createSpy.mock.calls[0][0];
    expect(blobArg).toBeInstanceOf(Blob);

    createSpy.mockRestore();
    revokeSpy.mockRestore();
  });
});

describe("ReportPage", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function renderReport(role: string | null = "analyst") {
    return render(
      <AuthAs role={role}>
        <MemoryRouter
          initialEntries={[`/reports/${REPORT_ID}`]}
        >
          <Routes>
            <Route path="/reports/:reportId" element={<ReportPage />} />
          </Routes>
        </MemoryRouter>
      </AuthAs>,
    );
  }

  it("renders markdown content as plain text (no HTML conversion)", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          report_id: REPORT_ID,
          format: "markdown",
          metadata: {},
          content: "# Heading\n<script>alert(1)</script>",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const { container } = renderReport();
    // The markdown heading text appears verbatim — not parsed into markup.
    const pre = await screen.findByText(/# Heading/);
    expect(pre.tagName).toBe("PRE");
    // The embedded script tag is inert text, not a live element.
    expect(container.querySelector("script")).toBeNull();
    // The "# Heading" markdown was NOT converted into a heading element
    // inside the report body.
    expect(pre.querySelector("h1")).toBeNull();
    expect(pre.textContent).toContain("<script>alert(1)</script>");
  });

  it("offers copy and download actions", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          report_id: REPORT_ID,
          format: "json",
          metadata: {},
          content: { hello: "world" },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const createSpy = vi
      .spyOn(URL, "createObjectURL")
      .mockReturnValue("blob:fake");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);

    renderReport();
    // Locale-tolerant: query by data-testid so the test works regardless of
    // whether the button label is English ("Download report") or Turkish
    // ("Raporu indir").
    const downloadBtn = await screen.findByTestId("report-download");
    expect(downloadBtn).toBeInTheDocument();
    expect(screen.getByTestId("report-copy")).toBeInTheDocument();

    await userEvent.click(downloadBtn);
    expect(createSpy).toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it("renders a stored JSON enrichment as the layered analyst report with collapsed raw content", async () => {
    fetchMock.mockResolvedValueOnce(
      reportResponse({ report_id: REPORT_ID, format: "json", metadata: {}, content: ENRICHMENT_CONTENT }),
    );
    renderReport("admin");
    expect(await screen.findByTestId("analyst-report")).toBeInTheDocument();
    expect(screen.getByText("T1090")).toBeInTheDocument();
    // Ham içerik başlangıçta kapalı; kopyala/indir yine erişilebilir.
    expect(screen.getByTestId("report-download")).toBeInTheDocument();
    expect(screen.queryByText(/"abuse_confidence_score"/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Ham içeriği göster" }));
    expect(screen.getByText(/"abuse_confidence_score"/)).toBeInTheDocument();
  });

  it("shows the everyday report without raw content, IDs or download for a session without a role", async () => {
    fetchMock.mockResolvedValueOnce(
      reportResponse({ report_id: REPORT_ID, format: "json", metadata: {}, content: ENRICHMENT_CONTENT }),
    );
    const { container } = renderReport(null);
    expect(await screen.findByTestId("everyday-report")).toBeInTheDocument();
    expect(screen.queryByTestId("analyst-report")).not.toBeInTheDocument();
    expect(screen.queryByTestId("report-download")).not.toBeInTheDocument();
    expect(container.textContent).not.toContain("T1090");
    expect(container.textContent).not.toContain("abuse_confidence_score");
    expect(container.textContent).not.toContain("409 reports");
  });

  it("does not show a technical markdown report in the everyday view", async () => {
    fetchMock.mockResolvedValueOnce(
      reportResponse({ report_id: REPORT_ID, format: "markdown", metadata: {}, content: "# Heading" }),
    );
    renderReport("viewer");
    expect(await screen.findByTestId("report-plain-unavailable")).toBeInTheDocument();
    expect(screen.queryByText(/# Heading/)).not.toBeInTheDocument();
  });
});
