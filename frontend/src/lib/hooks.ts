import { useCallback, useEffect, useRef, useState } from "react";

/** Moves keyboard and screen reader focus to the page heading when a screen opens. */
export function useFocusOnMount<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return ref;
}

type Clock = { deadline: number; now: number };

/**
 * Counts down a fixed session length while `active` is true, then calls
 * onExpire. Scrolling, typing and ranking do not reset it. Only extend(),
 * called when the voter selects "Keep voting", starts a new full session.
 *
 * The deadline is a wall-clock time, so a throttled background tab cannot
 * stretch the session.
 */
export function useSessionTimer(active: boolean, minutes: number, onExpire: () => void) {
  const total = minutes * 60;
  const [clock, setClock] = useState<Clock | null>(null);
  const latest = useRef(onExpire);
  latest.current = onExpire;

  useEffect(() => {
    if (!active) {
      setClock(null);
      return;
    }
    const now = Date.now();
    setClock({ deadline: now + total * 1000, now });
    const timer = window.setInterval(() => {
      setClock((c) => (c ? { ...c, now: Date.now() } : c));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [active, total]);

  const secondsLeft = clock ? Math.max(0, Math.ceil((clock.deadline - clock.now) / 1000)) : total;
  const expired = clock !== null && secondsLeft === 0;

  useEffect(() => {
    if (expired) latest.current();
  }, [expired]);

  const extend = useCallback(() => {
    const now = Date.now();
    setClock({ deadline: now + total * 1000, now });
  }, [total]);

  return { secondsLeft, extend };
}

/** 605 becomes "10:05". */
export function formatClock(seconds: number): string {
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}
