import { getCacheStats } from "@/lib/api";
import { useQuery } from "./useAsync";

export function useCacheStats() {
  return useQuery((signal) => getCacheStats(signal));
}
