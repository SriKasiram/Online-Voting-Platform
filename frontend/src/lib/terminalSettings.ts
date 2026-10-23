/**
 * SR-15: how long an elector's session may sit finished or abandoned on this device before it is
 * reset. The values can be lowered so a demo can be recorded quickly, but nothing turns the reset
 * off: a missing, non-numeric, zero or negative value falls back to the default, and every value is
 * clamped to its range.
 */

export type SettingRange = { fallback: number; min: number; max: number };

// SR-15: 90 seconds without input, then a 30-second warning: 120 seconds in all counts as abandoned
export const IDLE_SECONDS: SettingRange = { fallback: 90, min: 5, max: 600 };
export const IDLE_WARNING_SECONDS: SettingRange = { fallback: 30, min: 5, max: 120 };
// SR-15: kept in step with the backend's POST_BALLOT_SESSION_SECONDS (SR-04), which is also 60
export const RECEIPT_SECONDS: SettingRange = { fallback: 60, min: 5, max: 120 };
// SR-15: at most 3 seconds, so the start page still comes back within 5 seconds of the trigger
export const RESET_LOGOUT_TIMEOUT_MS: SettingRange = { fallback: 3000, min: 500, max: 3000 };

export function readSetting(raw: unknown, { fallback, min, max }: SettingRange): number {
  // SR-15: Number("") is 0, so a blank value falls back just as zero does, and can never mean "never"
  const value = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() !== "" ? Number(raw) : NaN;
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}

export type TerminalSettings = {
  idleSeconds: number;
  idleWarningSeconds: number;
  receiptSeconds: number;
  logoutTimeoutMs: number;
};

export function terminalSettings(env: Record<string, unknown>): TerminalSettings {
  return {
    idleSeconds: readSetting(env.VITE_IDLE_SECONDS, IDLE_SECONDS),
    idleWarningSeconds: readSetting(env.VITE_IDLE_WARNING_SECONDS, IDLE_WARNING_SECONDS),
    receiptSeconds: readSetting(env.VITE_RECEIPT_SECONDS, RECEIPT_SECONDS),
    logoutTimeoutMs: readSetting(env.VITE_RESET_LOGOUT_TIMEOUT_MS, RESET_LOGOUT_TIMEOUT_MS),
  };
}

// SR-15: read once at build time (Vite inlines VITE_ values), the same on terminals and personal devices
export const TERMINAL: TerminalSettings = terminalSettings(import.meta.env);
