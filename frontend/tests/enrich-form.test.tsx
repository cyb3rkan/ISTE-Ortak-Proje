import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { EnrichForm } from "@/components/enrich/EnrichForm";

// EnrichForm UI labels are localised (Turkish). Use bilingual regexes for
// labels we still want to query semantically, and data-testid for the few
// elements where exact role/name matching is brittle across locales.
const RE_ANALYZE = /analyze|analiz et/i;
const RE_ANALYZING = /analyzing|analiz ediliyor/i;
const RE_REQUIRED_IOC = /enter an ioc|bir ioc değeri girin/i;

describe("EnrichForm", () => {
  it("does not submit an empty IOC", async () => {
    const onSubmit = vi.fn();
    render(<EnrichForm onSubmit={onSubmit} submitting={false} />);

    await userEvent.click(screen.getByTestId("enrich-submit"));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(RE_REQUIRED_IOC);
  });

  it("submits a valid IOC with the chosen type", async () => {
    const onSubmit = vi.fn();
    render(<EnrichForm onSubmit={onSubmit} submitting={false} />);

    await userEvent.type(screen.getByTestId("enrich-ioc"), "8.8.8.8");
    await userEvent.selectOptions(
      screen.getByTestId("enrich-ioc-type"),
      "ipv4",
    );
    await userEvent.click(screen.getByTestId("enrich-submit"));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith({
      ioc: "8.8.8.8",
      ioc_type: "ipv4",
      use_cache: true,
    });
  });

  it("trims surrounding whitespace before submitting", async () => {
    const onSubmit = vi.fn();
    render(<EnrichForm onSubmit={onSubmit} submitting={false} />);

    await userEvent.type(screen.getByTestId("enrich-ioc"), "   1.1.1.1   ");
    await userEvent.click(screen.getByTestId("enrich-submit"));

    expect(onSubmit.mock.calls[0][0].ioc).toBe("1.1.1.1");
  });

  it("disables the submit button while submitting", () => {
    render(<EnrichForm onSubmit={vi.fn()} submitting={true} />);
    const button = screen.getByTestId("enrich-submit");
    expect(button).toBeDisabled();
    expect(button).toHaveTextContent(RE_ANALYZING);
    // Sanity: when not submitting, the label should match RE_ANALYZE.
    // (We don't re-render here — this just documents the contract.)
    expect(RE_ANALYZE.test("Analyze")).toBe(true);
    expect(RE_ANALYZE.test("Analiz Et")).toBe(true);
  });
});

describe("EnrichForm report saving", () => {
  it("does not request a report by default", async () => {
    const onSubmit = vi.fn();
    render(<EnrichForm onSubmit={onSubmit} submitting={false} />);

    await userEvent.type(screen.getByTestId("enrich-ioc"), "8.8.8.8");
    await userEvent.click(screen.getByTestId("enrich-submit"));

    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty("save_report_format");
  });

  it.each([
    ["json", "json"],
    ["markdown", "markdown"],
  ])("requests a %s report when chosen", async (option, expected) => {
    const onSubmit = vi.fn();
    render(<EnrichForm onSubmit={onSubmit} submitting={false} />);

    await userEvent.type(screen.getByTestId("enrich-ioc"), "8.8.8.8");
    await userEvent.selectOptions(screen.getByLabelText(/rapor kaydet/i), option);
    await userEvent.click(screen.getByTestId("enrich-submit"));

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ save_report_format: expected }),
    );
  });

  it("offers a labelled, keyboard-reachable report selector", () => {
    render(<EnrichForm onSubmit={vi.fn()} submitting={false} />);
    const select = screen.getByLabelText(/rapor kaydet/i);
    expect(select.tagName).toBe("SELECT");
    expect(
      Array.from((select as HTMLSelectElement).options).map((o) => o.value),
    ).toEqual(["", "json", "markdown"]);
  });
});
