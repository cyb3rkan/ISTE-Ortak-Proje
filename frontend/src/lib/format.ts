/** Küçük sunum yardımcıları — yan etkisizdir, DOM erişimi içermez. */

import type { RiskLevel } from "@/types/api";

export function normalizeRiskLevel(
  level: string | undefined | null,
): RiskLevel {
  const up = (level ?? "").toUpperCase();

  if (
    up === "LOW" ||
    up === "MEDIUM" ||
    up === "HIGH" ||
    up === "CRITICAL"
  ) {
    return up;
  }

  return "UNKNOWN";
}

export function riskLevelClasses(level: RiskLevel): string {
  switch (level) {
    case "LOW":
      return "bg-risk-low/15 text-risk-low border-risk-low/40";

    case "MEDIUM":
      return "bg-risk-medium/15 text-risk-medium border-risk-medium/40";

    case "HIGH":
      return "bg-risk-high/15 text-risk-high border-risk-high/40";

    case "CRITICAL":
      return "bg-risk-critical/15 text-risk-critical border-risk-critical/40";

    default:
      return "bg-risk-unknown/15 text-risk-unknown border-risk-unknown/40";
  }
}

export function formatBytes(
  bytes: number | null | undefined,
): string {
  if (bytes === null || bytes === undefined) return "—";

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  const kb = bytes / 1024;

  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }

  return `${(kb / 1024).toFixed(2)} MB`;
}

export function formatNumber(
  value: number | null | undefined,
): string {
  if (value === null || value === undefined) return "—";

  return new Intl.NumberFormat().format(value);
}

export function formatPercent(
  value: number | null | undefined,
): string {
  if (value === null || value === undefined) return "—";

  // detection_confidence / ai_confidence değerleri 0..1 arası oranlardır.
  return `${Math.round(value * 100)}%`;
}

export function formatDuration(
  ms: number | null | undefined,
): string {
  if (ms === null || ms === undefined) return "—";

  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }

  return `${(ms / 1000).toFixed(2)} sn`;
}