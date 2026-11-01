import { enrichSingle } from "@/lib/api";
import type { EnrichRequest, EnrichmentDTO } from "@/types/api";
import { useMutation } from "./useAsync";

/** Manual-trigger mutation for single-IOC enrichment. */
export function useEnrich() {
  return useMutation<EnrichRequest, EnrichmentDTO>((payload, signal) =>
    enrichSingle(payload, signal),
  );
}
