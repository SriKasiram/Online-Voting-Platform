import { useCallback, useEffect, useRef, useState } from "react";
import { createIdleController, type IdleController } from "./idleController";

/**
 * SR-15: the idle controller for App. While `active`, it watches the window for input. From the
 * first input on, idleSeconds without any opens the warning, and warningSeconds more calls
 * onTimeout. Returns the seconds left while the warning is open (null otherwise) and the button's
 * handler.
 */
export function useIdleReset(active: boolean, idleSeconds: number, warningSeconds: number, onTimeout: () => void) {
  const [warningEndsAt, setWarningEndsAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const controller = useRef<IdleController | null>(null);
  const latest = useRef(onTimeout);
  latest.current = onTimeout;

  useEffect(() => {
    if (!active) return;
    const idle = createIdleController({
      target: window,
      idleMs: idleSeconds * 1000,
      warningMs: warningSeconds * 1000,
      onWarn: (endsAt) => {
        setNow(Date.now());
        setWarningEndsAt(endsAt);
      },
      onActive: () => setWarningEndsAt(null),
      onTimeout: () => {
        // SR-15: the warning goes as the reset starts, rather than showing 0 while logout runs
        setWarningEndsAt(null);
        latest.current();
      },
      // SR-15: App starts this on the freshly loaded start page, which holds nothing to clear yet
      armOnInput: true,
    });
    idle.start();
    controller.current = idle;
    return () => {
      idle.stop();
      controller.current = null;
      setWarningEndsAt(null);
    };
  }, [active, idleSeconds, warningSeconds]);

  // SR-15: the warning's countdown; the deadline itself belongs to the controller
  useEffect(() => {
    if (warningEndsAt === null) return;
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(tick);
  }, [warningEndsAt]);

  const stillHere = useCallback(() => controller.current?.stillHere(), []);
  const warningSecondsLeft = warningEndsAt === null ? null : Math.max(0, Math.ceil((warningEndsAt - now) / 1000));
  return { warningSecondsLeft, stillHere };
}
