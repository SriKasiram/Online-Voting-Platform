import { useEffect, useReducer, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { ApiError } from "../api/client";
import { getAuditLog, getTurnout, resetElector, verifyAuditChain, type AuditEntry, type Turnout } from "../api/staffClient";
import { Spinner } from "../components/Messages";
import {
  AUDIT_LIMITS,
  INITIAL_CONSOLE,
  RESET_DONE,
  canReset,
  chainSummary,
  consoleReducer,
  nextTabIndex,
  resetMessage,
  runRequest,
  tabsForRole,
  type ConsoleAction,
  type ConsoleState,
  type TabId,
} from "./consoleLogic";

const dateTime = new Intl.DateTimeFormat("en-AU", { dateStyle: "short", timeStyle: "medium" });
const clockTime = new Intl.DateTimeFormat("en-AU", { timeStyle: "medium" });

type Props = {
  role: string;
  // SR-06: called on a 401, with the message the sign-in page shows
  onSessionEnded: (message: string) => void;
};

// SR-05: staff console: role-based views of the existing admin routes, after the SR-06 sign-in.
// Everything is rendered as plain text by React; nothing is kept outside this component's memory
// (SR-09), and it all goes when the console closes.
export default function StaffConsole({ role, onSessionEnded }: Props) {
  const tabs = tabsForRole(role);
  const [state, dispatch] = useReducer(consoleReducer, INITIAL_CONSOLE);
  const [active, setActive] = useState<TabId | null>(tabs[0]?.id ?? null);
  const [focusPanel, setFocusPanel] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const loadedOnce = useRef(false);

  // SR-05: a run of one admin request, shared by every tab
  function run<T>(tab: TabId, call: () => Promise<T>, onResult: (result: T) => void, failed: (error: unknown) => string) {
    return runRequest({ tab, call, onResult, failed, dispatch, onSessionEnded });
  }

  function loadTurnout() {
    void run("turnout", getTurnout, (data) => dispatch({ type: "turnout", data, at: new Date() }), (error) =>
      error instanceof ApiError && error.status === 404 ? "There is no election to show yet." : "Turnout could not be loaded. Try again.",
    );
  }

  // SR-05: the turnout loads once when the console opens, for both roles
  useEffect(() => {
    if (loadedOnce.current || !tabs.some((tab) => tab.id === "turnout")) return;
    loadedOnce.current = true;
    loadTurnout();
  }, []);

  // SR-05: choosing a tab with the mouse, Enter or Space moves focus to its panel heading
  useEffect(() => {
    if (focusPanel > 0) headingRef.current?.focus();
  }, [focusPanel]);

  function onTabKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = nextTabIndex(index, event.key, tabs.length);
    if (next === null) return;
    event.preventDefault();
    setActive(tabs[next].id);
    tabRefs.current[next]?.focus();
  }

  if (tabs.length === 0 || active === null) {
    return <p>This account has no staff functions.</p>;
  }
  const current = tabs.find((tab) => tab.id === active) ?? tabs[0];

  return (
    <div className="console">
      <div className="tabs" role="tablist" aria-label="Staff functions">
        {tabs.map((tab, index) => (
          <button
            key={tab.id}
            ref={(element) => {
              tabRefs.current[index] = element;
            }}
            type="button"
            role="tab"
            id={`tab-${tab.id}`}
            className="tab"
            aria-selected={tab.id === current.id}
            aria-controls={`panel-${tab.id}`}
            tabIndex={tab.id === current.id ? 0 : -1}
            onClick={() => {
              setActive(tab.id);
              setFocusPanel((n) => n + 1);
            }}
            onKeyDown={(event) => onTabKey(event, index)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <section className="tabpanel" role="tabpanel" id={`panel-${current.id}`} aria-labelledby={`tab-${current.id}`}>
        <h2 ref={headingRef} tabIndex={-1}>
          {current.label}
        </h2>
        {current.id === "turnout" && <TurnoutPanel state={state} onRefresh={loadTurnout} />}
        {current.id === "audit" && <AuditPanel state={state} dispatch={dispatch} run={run} />}
        {current.id === "verify" && <VerifyPanel state={state} dispatch={dispatch} run={run} />}
        {current.id === "reset" && <ResetPanel state={state} dispatch={dispatch} run={run} />}
      </section>
    </div>
  );
}

type Run = <T>(tab: TabId, call: () => Promise<T>, onResult: (result: T) => void, failed: (error: unknown) => string) => Promise<void>;
type PanelProps = { state: ConsoleState; dispatch: (action: ConsoleAction) => void; run: Run };

// SR-05: the aria-live region of a tab: its result or failure, as text
function Status({ text }: { text: string }) {
  return (
    <p className="console-status" role="status" aria-live="polite">
      {text}
    </p>
  );
}

function BusyLabel({ busy, label }: { busy: boolean; label: string }) {
  return busy ? (
    <>
      <Spinner />
      {label}
    </>
  ) : (
    <>{label}</>
  );
}

// SR-05: staff console: turnout (GET /api/admin/turnout), counts only, never an elector
function TurnoutPanel({ state, onRefresh }: { state: ConsoleState; onRefresh: () => void }) {
  const turnout: Turnout | undefined = state.turnout?.data;
  return (
    <div className="stack">
      <div className="console-actions">
        <button type="button" className="btn btn-secondary" onClick={onRefresh} disabled={state.busy} aria-busy={state.busy}>
          <BusyLabel busy={state.busy} label="Refresh" />
        </button>
        {state.turnout && <p className="muted">Last updated {clockTime.format(state.turnout.loadedAt)}</p>}
      </div>
      <Status text={state.messages.turnout} />
      {turnout && (
        <div className="table-wrap">
          <table className="data-table">
            <caption>{turnout.election}</caption>
            <thead>
              <tr>
                <th scope="col">Division</th>
                <th scope="col" className="num">
                  Issued, not yet voted
                </th>
                <th scope="col" className="num">
                  Voted
                </th>
              </tr>
            </thead>
            <tbody>
              {turnout.divisions.map((row) => (
                <tr key={row.division}>
                  <th scope="row">{row.division}</th>
                  <td className="num">{row.issued}</td>
                  <td className="num">{row.voted}</td>
                </tr>
              ))}
            </tbody>
            <tfoot>
              <tr>
                <th scope="row">Total</th>
                <td className="num">{turnout.total.issued}</td>
                <td className="num">{turnout.total.voted}</td>
              </tr>
            </tfoot>
          </table>
        </div>
      )}
    </div>
  );
}

// SR-05: staff console: the SR-16 audit log (GET /api/admin/audit-log), the fields the route returns
function AuditPanel({ state, dispatch, run }: PanelProps) {
  function load() {
    void run("audit", () => getAuditLog(state.auditLimit), (entries) => dispatch({ type: "audit", entries }), () =>
      "The audit log could not be loaded. Try again.",
    );
  }
  const entries: AuditEntry[] | null = state.audit;
  return (
    <div className="stack">
      <div className="console-actions">
        <div className="field field-inline">
          <label htmlFor="audit-limit">Entries</label>
          <select
            id="audit-limit"
            className="input input-short"
            value={state.auditLimit}
            onChange={(event) => dispatch({ type: "limit", limit: Number(event.target.value) })}
            disabled={state.busy}
          >
            {AUDIT_LIMITS.map((limit) => (
              <option key={limit} value={limit}>
                {limit}
              </option>
            ))}
          </select>
        </div>
        <button type="button" className="btn btn-secondary" onClick={load} disabled={state.busy} aria-busy={state.busy}>
          <BusyLabel busy={state.busy} label="Load" />
        </button>
      </div>
      <Status text={state.messages.audit} />
      {entries && (
        <div className="table-wrap">
          <table className="data-table">
            <caption>The first {entries.length} audit entries, oldest first</caption>
            <thead>
              <tr>
                <th scope="col" className="num">
                  ID
                </th>
                <th scope="col">Time</th>
                <th scope="col">Event type</th>
                <th scope="col">Actor</th>
                <th scope="col">Hash (first 16)</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <td className="num">{entry.id}</td>
                  <td>{dateTime.format(new Date(entry.created_at))}</td>
                  <td className="mono">{entry.event_type}</td>
                  <td className="mono">{entry.actor}</td>
                  <td className="mono">{entry.hash.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// SR-05: staff console: the SR-16 chain check (GET /api/admin/audit-log/verify)
function VerifyPanel({ state, dispatch, run }: PanelProps) {
  function check() {
    void run("verify", verifyAuditChain, (result) => dispatch({ type: "chain", result }), () => "The check could not be run. Try again.");
  }
  const chain = state.chain;
  return (
    <div className="stack">
      <p>Recomputes the hash of every audit entry on the server and checks each links to the one before.</p>
      <div className="console-actions">
        <button type="button" className="btn btn-secondary" onClick={check} disabled={state.busy} aria-busy={state.busy}>
          <BusyLabel busy={state.busy} label="Run check" />
        </button>
      </div>
      <Status text={state.messages.verify} />
      {chain && (
        <dl className={chain.ok ? "result result-pass" : "result result-fail"}>
          <dt>Result</dt>
          <dd>
            <strong>{chain.ok ? "PASS" : "FAIL"}</strong>
          </dd>
          {chain.ok ? (
            <>
              <dt>Entries checked</dt>
              <dd>{chain.entries}</dd>
            </>
          ) : (
            <>
              <dt>First bad entry</dt>
              <dd>{chain.first_bad_id}</dd>
            </>
          )}
          <dt>Summary</dt>
          <dd>{chainSummary(chain)}</dd>
        </dl>
      )}
    </div>
  );
}

// SR-05: staff console: reset an abandoned ballot (POST /api/admin/electors/{roll_id}/reset)
export function ResetPanel({ state, dispatch, run }: PanelProps) {
  const [rollId, setRollId] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!canReset(rollId, confirmed, state.busy)) return;
    const target = rollId;
    // SR-05: the field and the confirmation are cleared after every attempt
    setRollId("");
    setConfirmed(false);
    void run(
      "reset",
      () => resetElector(target),
      () => dispatch({ type: "message", tab: "reset", message: RESET_DONE }),
      resetMessage,
    );
  }

  return (
    <form className="stack" onSubmit={submit} noValidate>
      <p>Clears an abandoned ballot for an elector who was issued a ballot but has not voted. A cast ballot can never be reset.</p>
      <div className="field">
        <label htmlFor="reset-roll-id">Roll ID</label>
        <input
          id="reset-roll-id"
          className="input mono"
          value={rollId}
          onChange={(event) => setRollId(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <label className="check">
        <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
        <span>I have checked the roll ID, and this elector was issued a ballot but has not voted.</span>
      </label>
      <div className="console-actions">
        <button type="submit" className="btn btn-danger" disabled={!canReset(rollId, confirmed, state.busy)} aria-busy={state.busy}>
          <BusyLabel busy={state.busy} label="Reset" />
        </button>
      </div>
      <Status text={state.messages.reset} />
    </form>
  );
}
