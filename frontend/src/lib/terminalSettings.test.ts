import { describe, expect, it } from "vitest";
import {
  IDLE_SECONDS,
  IDLE_WARNING_SECONDS,
  RECEIPT_SECONDS,
  RESET_LOGOUT_TIMEOUT_MS,
  TERMINAL,
  readSetting,
  terminalSettings,
  type SettingRange,
} from "./terminalSettings";

const DEFAULTS = { idleSeconds: 90, idleWarningSeconds: 30, receiptSeconds: 60, logoutTimeoutMs: 3000 };

describe("SR-15: reset settings", () => {
  it("SR-15: missing values use the defaults", () => {
    expect(terminalSettings({})).toEqual(DEFAULTS);
  });

  it("SR-15: whatever frontend/.env sets, the values the app uses are inside their ranges", () => {
    const within = (value: number, { min, max }: SettingRange) => value >= min && value <= max;

    expect(within(TERMINAL.idleSeconds, IDLE_SECONDS)).toBe(true);
    expect(within(TERMINAL.idleWarningSeconds, IDLE_WARNING_SECONDS)).toBe(true);
    expect(within(TERMINAL.receiptSeconds, RECEIPT_SECONDS)).toBe(true);
    expect(within(TERMINAL.logoutTimeoutMs, RESET_LOGOUT_TIMEOUT_MS)).toBe(true);
  });

  it("SR-15: non-numeric or blank values use the defaults", () => {
    for (const raw of ["", " ", "abc", "12abc", "NaN", "Infinity", undefined, null, true]) {
      const all = { VITE_IDLE_SECONDS: raw, VITE_IDLE_WARNING_SECONDS: raw, VITE_RECEIPT_SECONDS: raw, VITE_RESET_LOGOUT_TIMEOUT_MS: raw };
      expect(terminalSettings(all), String(raw)).toEqual(DEFAULTS);
    }
  });

  it("SR-15: zero or negative values cannot disable the reset", () => {
    for (const raw of ["0", "-1", "-600", "0.0"]) {
      const all = { VITE_IDLE_SECONDS: raw, VITE_IDLE_WARNING_SECONDS: raw, VITE_RECEIPT_SECONDS: raw, VITE_RESET_LOGOUT_TIMEOUT_MS: raw };
      expect(terminalSettings(all), raw).toEqual(DEFAULTS);
    }
  });

  it("SR-15: values are clamped to their ranges", () => {
    expect(
      terminalSettings({
        VITE_IDLE_SECONDS: "1",
        VITE_IDLE_WARNING_SECONDS: "2",
        VITE_RECEIPT_SECONDS: "3",
        VITE_RESET_LOGOUT_TIMEOUT_MS: "100",
      }),
    ).toEqual({ idleSeconds: 5, idleWarningSeconds: 5, receiptSeconds: 5, logoutTimeoutMs: 500 });
    expect(
      terminalSettings({
        VITE_IDLE_SECONDS: "99999",
        VITE_IDLE_WARNING_SECONDS: "99999",
        VITE_RECEIPT_SECONDS: "99999",
        VITE_RESET_LOGOUT_TIMEOUT_MS: "99999",
      }),
    ).toEqual({ idleSeconds: 600, idleWarningSeconds: 120, receiptSeconds: 120, logoutTimeoutMs: 3000 });
  });

  it("SR-15: values inside the range are kept, so a demo can use short timers", () => {
    expect(
      terminalSettings({
        VITE_IDLE_SECONDS: "10",
        VITE_IDLE_WARNING_SECONDS: " 5 ",
        VITE_RECEIPT_SECONDS: "15",
        VITE_RESET_LOGOUT_TIMEOUT_MS: "1500",
      }),
    ).toEqual({ idleSeconds: 10, idleWarningSeconds: 5, receiptSeconds: 15, logoutTimeoutMs: 1500 });
  });

  it("SR-15: whatever the values, idle plus warning stays finite and the reset still fits in 5 seconds", () => {
    const worst = terminalSettings({ VITE_IDLE_SECONDS: "1e9", VITE_IDLE_WARNING_SECONDS: "1e9", VITE_RESET_LOGOUT_TIMEOUT_MS: "1e9" });

    expect(worst.idleSeconds + worst.idleWarningSeconds).toBeLessThanOrEqual(720);
    expect(worst.logoutTimeoutMs).toBeLessThanOrEqual(3000);
    expect(readSetting("7.6", { fallback: 1, min: 1, max: 10 })).toBe(8);
  });
});
