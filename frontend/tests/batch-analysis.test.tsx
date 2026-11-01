import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { BatchForm } from "@/components/batch/BatchForm";
import { BatchResultsTable } from "@/components/batch/BatchResultsTable";
import { BatchSummary } from "@/components/batch/BatchSummary";
import { parseBatchInput, validateBatch } from "@/lib/batch";
import type { BatchErrorItem, EnrichmentDTO } from "@/types/api";

function makeResult(
  ioc: string,
  score: number,
  level: string,
  overrides: Partial<EnrichmentDTO> = {},
): EnrichmentDTO {
  return {
    ioc,
    ioc_type: "ipv4",
    risk: { score, level, reasons: [] },
    providers: [],
    mitre: [],
    meta: {},
    ...overrides,
  };
}

// Locale-tolerant validation phrasing. The helper messages are Turkish,
// but the contract we care about is "non-empty error string mentioning the
// IOC count or the 50-cap". We match either localisation.
const RE_AT_LEAST_ONE = /at least one|en az bir ioc/i;
const RE_MAX_50 = /maximum is 50|maksimum.*50/i;
// The batch UI is Turkish; label/text queries use the Turkish strings.
const RE_BATCH_INPUT = /her satıra bir/i;

describe("batch parsing helpers", () => {
  it("drops empty lines and deduplicates", () => {
    const parsed = parseBatchInput("8.8.8.8\n\n  8.8.8.8 \n1.1.1.1\n");
    expect(parsed.iocs).toEqual(["8.8.8.8", "1.1.1.1"]);
    expect(parsed.duplicatesRemoved).toBe(1);
  });

  it("rejects an empty batch", () => {
    expect(validateBatch(parseBatchInput("   \n  "))).toMatch(RE_AT_LEAST_ONE);
  });

  it("rejects more than 50 IOCs", () => {
    const text = Array.from({ length: 51 }, (_, i) => `1.1.1.${i}`).join("\n");
    expect(validateBatch(parseBatchInput(text))).toMatch(RE_MAX_50);
  });
});

describe("BatchForm", () => {
  it("does not submit an empty batch", async () => {
    const onSubmit = vi.fn();
    render(<BatchForm onSubmit={onSubmit} submitting={false} />);
    await userEvent.click(screen.getByTestId("batch-submit"));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("shows a validation error for 51 IOCs", async () => {
    const onSubmit = vi.fn();
    render(<BatchForm onSubmit={onSubmit} submitting={false} />);
    const text = Array.from({ length: 51 }, (_, i) => `1.1.1.${i}`).join("\n");
    await userEvent.click(screen.getByLabelText(RE_BATCH_INPUT));
    await userEvent.paste(text);
    await userEvent.click(screen.getByTestId("batch-submit"));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(RE_MAX_50);
  });

  it("surfaces a duplicate count to the user", async () => {
    render(<BatchForm onSubmit={vi.fn()} submitting={false} />);
    await userEvent.click(screen.getByLabelText(RE_BATCH_INPUT));
    await userEvent.paste("8.8.8.8\n8.8.8.8\n1.1.1.1");
    expect(screen.getByText(/Yok sayılan tekrar:/i)).toBeInTheDocument();
  });

  it("submits a deduplicated payload", async () => {
    const onSubmit = vi.fn();
    render(<BatchForm onSubmit={onSubmit} submitting={false} />);
    await userEvent.click(screen.getByLabelText(RE_BATCH_INPUT));
    await userEvent.paste("8.8.8.8\n8.8.8.8\n1.1.1.1");
    await userEvent.click(screen.getByTestId("batch-submit"));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit.mock.calls[0][0]).toEqual({
      iocs: ["8.8.8.8", "1.1.1.1"],
      ioc_type: "auto",
      use_cache: true,
    });
  });
});

describe("BatchResultsTable", () => {
  const results = [
    makeResult("9.9.9.9", 90, "CRITICAL"),
    makeResult("1.1.1.1", 10, "LOW"),
  ];
  const errors: Array<BatchErrorItem & Record<string, unknown>> = [
    { ioc: "bad-ioc", error_type: "validation_error", message: "Invalid IOC." },
  ];

  it("renders rows for each successful result", () => {
    render(
      <MemoryRouter>
        <BatchResultsTable results={results} errors={[]} />
      </MemoryRouter>,
    );
    expect(screen.getByText("9.9.9.9")).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument();
  });

  it("renders a failed-items section", () => {
    render(
      <MemoryRouter>
        <BatchResultsTable results={results} errors={errors} />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Başarısız kayıtlar \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText("bad-ioc")).toBeInTheDocument();
  });

  it("filters to a single risk level", async () => {
    render(
      <MemoryRouter>
        <BatchResultsTable results={results} errors={[]} />
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Kritik" }));
    const table = screen.getByRole("table");
    expect(within(table).getByText("9.9.9.9")).toBeInTheDocument();
    expect(within(table).queryByText("1.1.1.1")).not.toBeInTheDocument();
  });
});

describe("batch UI localisation", () => {
  it("renders the form in Turkish", () => {
    render(<BatchForm onSubmit={vi.fn()} submitting={false} />);
    expect(screen.getByLabelText(RE_BATCH_INPUT)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Tür$/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Cache kullan/)).toBeInTheDocument();
    expect(screen.getByTestId("batch-submit")).toHaveTextContent(/^Analiz Et$/);
  });

  it("shows the IOC count on the submit button", async () => {
    render(<BatchForm onSubmit={vi.fn()} submitting={false} />);
    await userEvent.click(screen.getByLabelText(RE_BATCH_INPUT));
    await userEvent.paste("8.8.8.8\n1.1.1.1");
    expect(screen.getByTestId("batch-submit")).toHaveTextContent("Analiz Et (2 IOC)");
  });

  it("shows a Turkish busy label while submitting", () => {
    render(<BatchForm onSubmit={vi.fn()} submitting />);
    expect(screen.getByTestId("batch-submit")).toHaveTextContent(/Analiz ediliyor/);
  });

  it("localises table headings, filters, summary and error types", () => {
    render(
      <MemoryRouter>
        <BatchResultsTable
          results={[makeResult("9.9.9.9", 90, "CRITICAL")]}
          errors={[
            { ioc: "x", error_type: "validation_error", message: "m1" },
            { ioc: "y", error_type: "deadline_exceeded", message: "m2" },
            { ioc: "z", error_type: "some_new_code", message: "m3" },
          ]}
        />
        <BatchSummary summary={{ total: 3, success: 1, failed: 2, unique: 3, duplicates_removed: 0 }} />
      </MemoryRouter>,
    );
    for (const name of ["Tümü", "Kritik", "Yüksek", "Orta", "Düşük", "Başarısız"]) {
      expect(screen.getByRole("button", { name })).toBeInTheDocument();
    }
    const table = screen.getByRole("table");
    for (const h of [/Tür/, /Skor/, /Seviye/, /Provider'lar/, /İnceleme/, /Rapor/]) {
      expect(within(table).getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    expect(screen.getByText("Toplu Sonuçlar")).toBeInTheDocument();
    expect(screen.getByText("Toplu Özet")).toBeInTheDocument();
    expect(screen.getByText(/Doğrulama hatası: m1/)).toBeInTheDocument();
    expect(screen.getByText(/Süre aşımı: m2/)).toBeInTheDocument();
    // Unknown codes fall back to the raw code rather than being hidden.
    expect(screen.getByText(/some_new_code: m3/)).toBeInTheDocument();
    for (const label of ["Toplam", "Başarılı", "Tekrar", "Benzersiz"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("gives the human-review marker an accessible name", () => {
    const flagged = makeResult("9.9.9.9", 90, "CRITICAL");
    (flagged as unknown as { ai_analysis: unknown }).ai_analysis = { requires_human_review: true };
    render(
      <MemoryRouter>
        <BatchResultsTable results={[flagged]} errors={[]} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("img", { name: /İnsan incelemesi gerekli/ })).toBeInTheDocument();
  });
});
