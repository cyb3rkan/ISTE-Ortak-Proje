import { getProviders } from "@/lib/api";
import { useQuery } from "./useAsync";

export function useProviders() {
  return useQuery((signal) => getProviders(signal));
}
