import { useEffect, useRef } from "react";

/** Moves keyboard and screen reader focus to the page heading when a screen opens. */
export function useFocusOnMount<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return ref;
}
