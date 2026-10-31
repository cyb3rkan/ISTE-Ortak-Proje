import { useEffect, useState } from "react";

function secondsUntil(until: number | null): number {
  return until === null ? 0 : Math.max(0, Math.ceil((until - Date.now()) / 1000));
}

/** `until` (epoch ms) zamanına kalan tam saniyeyi döndürür; null ise 0. */
export function useCountdown(until: number | null): number {
  const [seconds, setSeconds] = useState(() => secondsUntil(until));

  useEffect(() => {
    setSeconds(secondsUntil(until));
    if (until === null) return;
    const timer = setInterval(() => {
      const next = secondsUntil(until);
      setSeconds(next);
      if (next === 0) clearInterval(timer);
    }, 1000);
    return () => clearInterval(timer);
  }, [until]);

  return seconds;
}
