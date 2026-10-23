/**
 * SR-15: the receipt screen's countdown. The elector finishes by selecting Done, or the session
 * finishes for them when this reaches 0. The deadline is wall-clock time, so a throttled
 * background tab cannot stretch it.
 */
import type { IdleTimers } from "./idleController";
import { browserTimers } from "./terminalReset";

export type CountdownOptions = {
  seconds: number;
  onTick: (secondsLeft: number) => void;
  onTimeout: () => void;
  timers?: IdleTimers;
};

/** Starts counting down at once. Returns a function that stops it. */
export function startReceiptCountdown({ seconds, onTick, onTimeout, timers }: CountdownOptions): () => void {
  const clock = timers ?? { ...browserTimers, now: () => Date.now() };
  const deadline = clock.now() + seconds * 1000;
  let handle: unknown = null;
  let stopped = false;

  const tick = () => {
    if (stopped) return;
    const msLeft = deadline - clock.now();
    const secondsLeft = Math.max(0, Math.ceil(msLeft / 1000));
    onTick(secondsLeft);
    if (secondsLeft === 0) {
      stopped = true;
      onTimeout();
      return;
    }
    // Wakes on the next whole second, so the display never lags the deadline
    handle = clock.setTimeout(tick, msLeft % 1000 || 1000);
  };
  handle = clock.setTimeout(tick, 1000);

  return () => {
    stopped = true;
    if (handle !== null) clock.clearTimeout(handle);
  };
}

// SR-15: screen readers hear the countdown at these points only, not every second
export const ANNOUNCE_AT = [5, 10, 30];

/** The polite live region's text: changes only when a point in ANNOUNCE_AT is reached. */
export function countdownAnnouncement(secondsLeft: number): string {
  const mark = ANNOUNCE_AT.find((point) => secondsLeft <= point);
  return mark === undefined ? "" : `This screen will clear in ${mark} seconds.`;
}
