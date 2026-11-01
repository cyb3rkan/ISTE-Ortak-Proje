import { enrichBatch } from "@/lib/api";
import type { BatchEnrichRequest, BatchEnrichResponse } from "@/types/api";
import { useMutation } from "./useAsync";

/** Manual-trigger mutation for batch enrichment. */
export function useEnrichBatch() {
  return useMutation<BatchEnrichRequest, BatchEnrichResponse>(
    (payload, signal) => enrichBatch(payload, signal),
  );
}
