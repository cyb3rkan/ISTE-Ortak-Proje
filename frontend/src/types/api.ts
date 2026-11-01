/**
 * TypeScript mirror of the backend Pydantic DTOs
 * (`ioc_enricher/ioc_enricher/web/schemas.py`).
 *
 * These types intentionally mirror what the API *returns*; they are NOT a
 * place to add fields the backend does not send.
 */

// ---------------------------------------------------------------------------
// Errors (RFC 7807 problem+json)
// ---------------------------------------------------------------------------

export interface ProblemValidationError {
  loc: string[];
  msg: string;
  type: string;
}

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  request_id?: string | null;
  /** Present on 422 request-validation responses. */
  errors?: ProblemValidationError[];
  /** Present on 429 responses. */
  retry_after_seconds?: number;
}

// ---------------------------------------------------------------------------
// Allowed IOC types (wire values accepted by the backend)
// ---------------------------------------------------------------------------

export const IOC_TYPES = [
  "auto",
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "hash",
  "email",
] as const;

export type IocType = (typeof IOC_TYPES)[number];

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

export interface EnrichRequest {
  ioc: string;
  ioc_type?: IocType;
  use_cache?: boolean;
  save_report_format?: "json" | "markdown" | null;
}

export interface BatchEnrichRequest {
  iocs: string[];
  ioc_type?: IocType;
  use_cache?: boolean;
  save_report_format?: "json" | "markdown" | null;
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  providers_configured: number;
  ai_enabled: boolean;
}

export interface RiskDTO {
  score: number;
  level: string;
  reasons: string[];
  detection_confidence?: number | null;
  active_data_points?: string[] | null;
  /**
   * Optional numeric per-provider score contribution
   * (provider name -> points). Present when the backend's deterministic
   * scorer produced a breakdown; absent on older results.
   */
  breakdown?: Record<string, number> | null;
  /** Qualitative evidence summary: very_strong | strong | moderate | weak | none. */
  evidence_strength?: string | null;
  /** True when the IOC matches a known anti-malware test-file family (EICAR). */
  is_known_test_file?: boolean | null;
  test_file_family?: string | null;
  /** Note distinguishing operational risk from raw provider verdicts. */
  operational_risk_note?: string | null;
  /** VirusTotal malicious/total ratio (0..1) when available. */
  vt_detection_ratio?: number | null;
  /**
   * URL-mode pattern signal tokens (e.g. "ip_based_url",
   * "non_standard_port", "script_payload", "suspicious_path",
   * "plain_http_ip", "benign_host"). Empty or omitted for non-URL IOCs.
   */
  url_pattern_signals?: string[] | null;
  /**
   * Provider category labels normalised to canonical malicious tokens
   * (e.g. "known infection source", "malware", "phishing").
   */
  suspicious_categories?: string[] | null;
  /**
   * Canonical names of the deterministic floors/boosts that fired on top
   * of the per-provider envelope. Lets the UI explain a final score that
   * exceeds the sum of provider contributions.
   */
  applied_floors?: string[] | null;
  /**
   * Human-readable calibration note. Present only when the final score is
   * higher than the provider-only sum.
   */
  calibration_note?: string | null;
  /**
   * Itemised non-provider score components. Invariant:
   * sum(breakdown) + sum(points) === score.
   */
  score_adjustments?: ScoreAdjustmentDTO[] | null;
  /**
   * Provider coverage: "complete" | "partial" | "insufficient_data".
   * Distinguishes absence of evidence from evidence of benignness;
   * it never changes score/level.
   */
  evidence_status?: EvidenceStatus | string | null;
  /** { queried, responded, failed, not_found } provider counts. */
  provider_coverage?: Record<string, number> | null;
  /** Providers that failed (error / timeout / rate limit). */
  unavailable_providers?: string[] | null;
}

export type EvidenceStatus = "complete" | "partial" | "insufficient_data";

export interface ScoreAdjustmentDTO {
  key: string;
  label: string;
  points: number;
}

export interface ProviderResultDTO {
  name: string;
  status: string;
  data_summary: Record<string, unknown>;
  error?: string | null;
  response_time_ms?: number | null;
}

export interface MitreTechniqueDTO {
  tactic?: string | null;
  technique_id?: string | null;
  technique_name?: string | null;
  description?: string | null;
  /** "observed" | "reported" | "contextual" — evidence directness. */
  basis?: string | null;
  /** Short statement of the supporting provider signal. */
  evidence?: string | null;
}

export interface AIAnalysisDTO {
  summary: string;
  key_findings: string[];
  recommendations: string[];
  analyst_note: string;
  detection_confidence: number;
  ai_confidence: number;
  requires_human_review: boolean;
  why_malicious: string[];
  why_benign: string[];
  weak_signals: Array<Record<string, string>>;
  prioritized_recommendations: Array<Record<string, string>>;
  tags: string[];
  confidence: number;
  audit_trail?: Record<string, unknown> | null;
  /**
   * "ai" = validated model narrative; "deterministic" = rule-based fallback
   * (AI disabled, skipped, failed or rejected — audit_trail may still show the
   * attempted call). Absent from older backends. Never changes score/evidence.
   */
  source?: AIAnalysisSource | null;
}

export type AIAnalysisSource = "ai" | "deterministic";

export interface EnrichmentDTO {
  ioc: string;
  ioc_type: string;
  risk: RiskDTO;
  providers: ProviderResultDTO[];
  mitre: MitreTechniqueDTO[];
  ai_analysis?: AIAnalysisDTO | null;
  meta: Record<string, unknown>;
  report_id?: string | null;
}

/** One failed item in a batch response (see web/service.py). */
export interface BatchErrorItem {
  ioc: string;
  error_type: string;
  message: string;
  request_id?: string | null;
}

/** Summary block of a batch response. */
export interface BatchSummary {
  total: number;
  unique: number;
  success: number;
  failed: number;
  duplicates_removed: number;
}

export interface BatchEnrichResponse {
  results: EnrichmentDTO[];
  // The backend currently sends exactly BatchErrorItem-shaped objects, but we
  // keep the index signature so an extra field never breaks parsing.
  errors: Array<BatchErrorItem & Record<string, unknown>>;
  summary: Partial<BatchSummary> & Record<string, unknown>;
}

export interface ProviderStatusDTO {
  name: string;
  enabled: boolean;
  configured: boolean;
  status: string;
  last_error?: string | null;
}

export interface ProviderStatusResponse {
  providers: ProviderStatusDTO[];
  ai_enabled: boolean;
}

export interface CacheStatsDTO {
  entries: number;
  hits?: number | null;
  misses?: number | null;
  size_bytes?: number | null;
  ttl_hours?: number | null;
}

/** Shape returned by GET /api/v1/reports/{id} (see report_store.get_report). */
export interface ReportResponse {
  report_id: string;
  format: string;
  created_at?: string | null;
  metadata: Record<string, unknown>;
  content: unknown;
}
