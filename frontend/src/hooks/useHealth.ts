import { getHealth } from "@/lib/api";
import { useQuery } from "./useAsync";

export function useHealth() {
  return useQuery((signal) => getHealth(signal));
}
