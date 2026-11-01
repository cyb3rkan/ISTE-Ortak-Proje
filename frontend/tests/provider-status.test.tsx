import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProviderStatusGrid } from "@/components/providers/ProviderStatusGrid";
import type { ProviderStatusDTO } from "@/types/api";

const PROVIDERS: ProviderStatusDTO[] = [
  {
    name: "VirusTotal",
    configured: true,
    enabled: true,
    status: "active",
    last_error: null,
  },
  {
    name: "Shodan",
    configured: false,
    enabled: false,
    status: "disabled",
    last_error: "<script>alert('xss')</script> connection refused",
  },
];

describe("ProviderStatusGrid", () => {
  it("renders a card per provider", () => {
    render(<ProviderStatusGrid providers={PROVIDERS} />);
    expect(screen.getByText("VirusTotal")).toBeInTheDocument();
    expect(screen.getByText("Shodan")).toBeInTheDocument();
  });

  it("shows configured / enabled badges", () => {
    render(<ProviderStatusGrid providers={PROVIDERS} />);
    // Locale-tolerant: rely on stable data-testid wrappers rather than the
    // localised badge text ("Configured"/"Yapılandırıldı", etc.).
    expect(screen.getByTestId("badge-configured")).toBeInTheDocument();
    expect(screen.getByTestId("badge-no-api-key")).toBeInTheDocument();
    expect(screen.getByTestId("badge-enabled")).toBeInTheDocument();
    expect(screen.getByTestId("badge-disabled")).toBeInTheDocument();
  });

  it("renders last_error as text and never executes embedded HTML", () => {
    const { container } = render(<ProviderStatusGrid providers={PROVIDERS} />);
    // The error string is shown verbatim as text...
    expect(
      screen.getByText(/connection refused/i),
    ).toBeInTheDocument();
    // ...but the <script> tag is NOT a live DOM node.
    expect(container.querySelector("script")).toBeNull();
  });
});
