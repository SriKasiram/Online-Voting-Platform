/**
 * SR-15: notices an elector who has walked away. After idleMs with no input it warns, and after
 * warningMs more with no input it ends the session. There is no React here, so tests can drive it
 * with fake timers and a plain EventTarget.
 */
import { browserTimers, type Timers } from "./terminalReset";

// SR-15: any of these on the window means someone is at the screen
export const ACTIVITY_EVENTS = ["keydown", "pointerdown", "pointermove", "wheel", "touchstart"] as const;

// SR-15: pointermove fires many times a second; one restart a second is plenty
export const THROTTLE_MS = 1000;

export type IdleTimers = Timers & { now(): number };

export type ActivityTarget = Pick<EventTarget, "addEventListener" | "removeEventListener">;

export type IdleOptions = {
  target: ActivityTarget;
  idleMs: number;
  warningMs: number;
  /** The warning opens. endsAt is when the session will be reset, on the timers' clock. */
  onWarn: (endsAt: number) => void;
  /** Input arrived while the warning was open, so it closes. */
  onActive: () => void;
  onTimeout: () => void;
  /**
   * SR-15: wait for the first input before timing. A freshly loaded start page holds nothing to
   * clear, and every elector session begins with input there, so none goes untimed.
   */
  armOnInput?: boolean;
  timers?: IdleTimers;
};

export type IdleController = { start(): void; stop(): void; stillHere(): void };

const browserIdleTimers: IdleTimers = { ...browserTimers, now: () => Date.now() };

// SR-15: capture, so a component that stops an event's propagation cannot hide the activity
const LISTEN = { capture: true, passive: true } as const;

export function createIdleController(options: IdleOptions): IdleController {
  const timers = options.timers ?? browserIdleTimers;
  let timer: unknown = null;
  let running = false;
  let warning = false;
  let lastRestart = -Infinity;

  function schedule(callback: () => void, ms: number) {
    if (timer !== null) timers.clearTimeout(timer);
    timer = timers.setTimeout(callback, ms);
  }

  function restart() {
    lastRestart = timers.now();
    if (warning) {
      warning = false;
      options.onActive();
    }
    schedule(warn, options.idleMs);
  }

  function warn() {
    warning = true;
    options.onWarn(timers.now() + options.warningMs);
    schedule(expire, options.warningMs);
  }

  function expire() {
    stop();
    options.onTimeout();
  }

  function onInput() {
    if (!running || timers.now() - lastRestart < THROTTLE_MS) return;
    restart();
  }

  function start() {
    if (running) return;
    running = true;
    for (const type of ACTIVITY_EVENTS) options.target.addEventListener(type, onInput, LISTEN);
    if (!options.armOnInput) restart();
  }

  function stop() {
    if (!running) return;
    running = false;
    for (const type of ACTIVITY_EVENTS) options.target.removeEventListener(type, onInput, LISTEN);
    if (timer !== null) timers.clearTimeout(timer);
    timer = null;
    warning = false;
  }

  // SR-15: the "I'm still here" button always counts, even inside the throttle window, because a
  // screen reader can press it without any keydown or pointerdown reaching the window
  function stillHere() {
    if (running) restart();
  }

  return { start, stop, stillHere };
}

// SR-15: the SR-04 session warning and the idle warning never show together. The one that ends
// sooner wins, because that is the deadline the elector has to act on.
export function warningToShow(sessionSecondsLeft: number | null, idleSecondsLeft: number | null): "session" | "idle" | null {
  if (idleSecondsLeft === null) return sessionSecondsLeft === null ? null : "session";
  if (sessionSecondsLeft === null) return "idle";
  return sessionSecondsLeft < idleSecondsLeft ? "session" : "idle";
}
