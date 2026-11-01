/**
 * Tiny async-state primitive.
 *
 * We deliberately avoid TanStack Query here — the app has a handful of simple
 * reads and one mutation, and a 40-line hook keeps the dependency surface (and
 * the audit surface) small. Phase 4 can graduate to a cache library if needed.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { describeError } from "@/lib/api";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/** Runs `fn` once on mount (and on `deps` change), with abort on unmount. */
export function useQuery<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  deps: unknown[] = [],
): AsyncState<T> & { reload: () => void } {
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    error: null,
    loading: true,
  });
  const [nonce, setNonce] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    fnRef
      .current(controller.signal)
      .then((data) => {
        if (active) setState({ data, error: null, loading: false });
      })
      .catch((err: unknown) => {
        if (!active) return;
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({ data: null, error: describeError(err), loading: false });
      });
    return () => {
      active = false;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  return { ...state, reload };
}

/** Manually-triggered async action (used for the enrich form). */
export function useMutation<TArgs, TResult>(
  fn: (args: TArgs, signal: AbortSignal) => Promise<TResult>,
): {
  run: (args: TArgs) => Promise<void>;
  reset: () => void;
} & AsyncState<TResult> {
  const [state, setState] = useState<AsyncState<TResult>>({
    data: null,
    error: null,
    loading: false,
  });
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => controllerRef.current?.abort(),
    [],
  );

  const run = useCallback(
    async (args: TArgs) => {
      controllerRef.current?.abort();
      const controller = new AbortController();
      controllerRef.current = controller;
      setState({ data: null, error: null, loading: true });
      try {
        const data = await fn(args, controller.signal);
        if (!controller.signal.aborted) {
          setState({ data, error: null, loading: false });
        }
      } catch (err) {
        if (controller.signal.aborted) return;
        setState({ data: null, error: describeError(err), loading: false });
      }
    },
    [fn],
  );

  const reset = useCallback(
    () => setState({ data: null, error: null, loading: false }),
    [],
  );

  return { ...state, run, reset };
}
