import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { countdownAnnouncement, startReceiptCountdown } from "./receiptCountdown";
import { sessionEndHandlers, type ResetReason } from "./terminalReset";

// SR-15: the countdown wired to the reset the way Receipt and App wire it
function setUp(seconds = 60) {
  const reasons: ResetReason[] = [];
  const ends = sessionEndHandlers((reason) => reasons.push(reason));
  const ticks: number[] = [];
  const stop = startReceiptCountdown({ seconds, onTick: (left) => ticks.push(left), onTimeout: ends.receiptTimeout });
  return { reasons, ticks, stop, ends };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("SR-15: receipt screen", () => {
  it("SR-15: with no action, the reset runs with receipt_timeout at 60 seconds", () => {
    const { reasons, ticks } = setUp();

    vi.advanceTimersByTime(59_999);
    expect(reasons).toEqual([]);
    expect(ticks.at(-1)).toBe(1);

    vi.advanceTimersByTime(1);
    expect(ticks.at(-1)).toBe(0);
    expect(reasons).toEqual(["receipt_timeout"]);

    vi.advanceTimersByTime(60_000);
    expect(reasons).toEqual(["receipt_timeout"]);
  });

  it("SR-15: Done resets the terminal at once", () => {
    const { reasons, ends, stop } = setUp();
    vi.advanceTimersByTime(5_000);

    ends.done();
    stop(); // the receipt screen unmounts

    vi.advanceTimersByTime(120_000);
    expect(reasons).toEqual(["done"]);
  });

  it("SR-15: the visible countdown goes down one second at a time", () => {
    const { ticks } = setUp();

    vi.advanceTimersByTime(3_000);

    expect(ticks).toEqual([59, 58, 57]);
  });

  it("SR-15: a shorter demo value is honoured", () => {
    const { reasons } = setUp(5);

    vi.advanceTimersByTime(5_000);

    expect(reasons).toEqual(["receipt_timeout"]);
  });

  it("SR-15: the polite announcement changes only at 30, 10 and 5 seconds", () => {
    const texts = Array.from({ length: 60 }, (_, i) => countdownAnnouncement(60 - i));
    const changes = texts.filter((text, i) => i === 0 || text !== texts[i - 1]);

    expect(changes).toEqual([
      "",
      "This screen will clear in 30 seconds.",
      "This screen will clear in 10 seconds.",
      "This screen will clear in 5 seconds.",
    ]);
    expect(countdownAnnouncement(31)).toBe("");
    expect(countdownAnnouncement(30)).toBe("This screen will clear in 30 seconds.");
  });
});
