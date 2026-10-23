import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACTIVITY_EVENTS, createIdleController, warningToShow } from "./idleController";
import { sessionEndHandlers, type ResetReason } from "./terminalReset";

const SECOND = 1000;

// SR-15: the controller on a plain EventTarget, with the defaults (90 s idle, 30 s warning), and
// its timeout wired to the reset the way App wires it
function setUp(options: { armOnInput?: boolean } = {}) {
  const target = new EventTarget();
  const reasons: ResetReason[] = [];
  const ends = sessionEndHandlers((reason) => reasons.push(reason));
  const warnings: number[] = [];
  let closed = 0;
  const idle = createIdleController({
    target,
    idleMs: 90 * SECOND,
    warningMs: 30 * SECOND,
    onWarn: (endsAt) => warnings.push(endsAt),
    onActive: () => closed++,
    onTimeout: ends.idleTimeout,
    ...options,
  });
  const input = (type: string = "pointermove") => target.dispatchEvent(new Event(type));
  return { idle, input, reasons, warnings, closed: () => closed };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("SR-15: idle timer", () => {
  it("SR-15: no warning before 90 seconds, and the warning at 90 seconds", () => {
    const { idle, warnings } = setUp();
    idle.start();

    vi.advanceTimersByTime(90 * SECOND - 1);
    expect(warnings).toEqual([]);

    vi.advanceTimersByTime(1);
    expect(warnings).toEqual([Date.now() + 30 * SECOND]);
  });

  it("SR-15: no input at all resets the terminal with idle_timeout at 120 seconds", () => {
    const { idle, reasons } = setUp();
    idle.start();

    vi.advanceTimersByTime(120 * SECOND - 1);
    expect(reasons).toEqual([]);

    vi.advanceTimersByTime(1);
    expect(reasons).toEqual(["idle_timeout"]);

    vi.advanceTimersByTime(600 * SECOND);
    expect(reasons).toEqual(["idle_timeout"]);
  });

  it("SR-15: input during the warning closes it and restarts the full 90 seconds", () => {
    const { idle, input, reasons, warnings, closed } = setUp();
    idle.start();
    vi.advanceTimersByTime(100 * SECOND);
    expect(warnings).toHaveLength(1);

    input("keydown");

    expect(closed()).toBe(1);
    vi.advanceTimersByTime(90 * SECOND - 1);
    expect(warnings).toHaveLength(1);
    expect(reasons).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(warnings).toHaveLength(2);
  });

  it("SR-15: the I'm still here button closes the warning and restarts the timer", () => {
    const { idle, reasons, closed } = setUp();
    idle.start();
    vi.advanceTimersByTime(119 * SECOND);

    idle.stillHere();

    expect(closed()).toBe(1);
    vi.advanceTimersByTime(100 * SECOND);
    expect(reasons).toEqual([]);
  });

  it("SR-15: each kind of input before 90 seconds restarts the timer", () => {
    for (const type of ACTIVITY_EVENTS) {
      const { idle, input, warnings } = setUp();
      idle.start();
      vi.advanceTimersByTime(80 * SECOND);

      input(type);
      vi.advanceTimersByTime(80 * SECOND);

      expect(warnings, type).toEqual([]);
      idle.stop();
    }
  });

  it("SR-15: input is throttled to one restart a second", () => {
    const { idle, input, warnings } = setUp();
    idle.start(); // restart at 0 s

    vi.advanceTimersByTime(999);
    input(); // inside the first second: ignored
    vi.advanceTimersByTime(90 * SECOND - 999);
    expect(warnings).toHaveLength(1); // still warned 90 s after the start

    const { idle: second, input: inputSecond, warnings: secondWarnings } = setUp();
    second.start();
    vi.advanceTimersByTime(SECOND);
    inputSecond(); // a full second later: restarts
    vi.advanceTimersByTime(90 * SECOND - 1);
    expect(secondWarnings).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(secondWarnings).toHaveLength(1);
  });

  it("SR-15: a burst of pointermove events restarts the timer once", () => {
    const target = new EventTarget();
    const setTimeoutSpy = vi.fn((callback: () => void, ms: number) => setTimeout(callback, ms));
    const idle = createIdleController({
      target,
      idleMs: 90 * SECOND,
      warningMs: 30 * SECOND,
      onWarn: () => {},
      onActive: () => {},
      onTimeout: () => {},
      timers: { setTimeout: setTimeoutSpy, clearTimeout: (h) => clearTimeout(h as never), now: () => Date.now() },
    });
    idle.start();
    vi.advanceTimersByTime(5 * SECOND);

    for (let i = 0; i < 50; i++) target.dispatchEvent(new Event("pointermove"));

    // the start, then one restart for the whole burst
    expect(setTimeoutSpy).toHaveBeenCalledTimes(2);
  });

  it("SR-15: on a freshly loaded start page the timer waits for the first input", () => {
    const { idle, input, warnings, reasons } = setUp({ armOnInput: true });
    idle.start();

    vi.advanceTimersByTime(600 * SECOND);
    expect(warnings).toEqual([]);

    input("keydown");
    vi.advanceTimersByTime(120 * SECOND);
    expect(reasons).toEqual(["idle_timeout"]);
  });

  it("SR-15: stop removes the listeners and the timers (the receipt screen)", () => {
    const { idle, input, warnings, reasons } = setUp();
    idle.start();

    idle.stop();
    input();
    vi.advanceTimersByTime(600 * SECOND);

    expect(warnings).toEqual([]);
    expect(reasons).toEqual([]);
  });
});

describe("SR-15: the two warnings never show together", () => {
  it("SR-15: the one that ends sooner wins", () => {
    expect(warningToShow(null, null)).toBeNull();
    expect(warningToShow(45, null)).toBe("session");
    expect(warningToShow(null, 30)).toBe("idle");
    expect(warningToShow(20, 30)).toBe("session");
    expect(warningToShow(50, 30)).toBe("idle");
  });
});
