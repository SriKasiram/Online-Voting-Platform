import type { ReactNode } from "react";
import { AlertIcon, InfoIcon } from "./Icons";

/** Something the voter must fix. Screen readers announce it as soon as it appears. */
export function ErrorAlert({ children }: { children: ReactNode }) {
  return (
    <div className="alert" role="alert">
      <AlertIcon />
      <span>{children}</span>
    </div>
  );
}

/** Neutral information, such as why the voter was signed out. */
export function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="notice" role="status">
      <InfoIcon />
      <span>{children}</span>
    </div>
  );
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}
