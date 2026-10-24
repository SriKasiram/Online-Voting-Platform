import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { INITIAL_CONSOLE } from "./consoleLogic";
import StaffConsole, { ResetPanel } from "./StaffConsole";

// SR-05: the console's first render, as markup (react-dom/server: no jsdom, no new package).
// Effects do not run here, so no request is made.
const noop = () => undefined;
const run = () => Promise.resolve();

describe("SR-05: staff console markup", () => {
  it("SR-05: a polling official gets an accessible tab list with Turnout selected", () => {
    const html = renderToStaticMarkup(<StaffConsole role="polling_official" onSessionEnded={noop} />);

    expect(html).toContain('role="tablist"');
    expect(html.match(/role="tab"/g)).toHaveLength(2);
    expect(html).toMatch(/<button[^>]*role="tab"[^>]*aria-selected="true"[^>]*>Turnout<\/button>/);
    expect(html).toMatch(/<button[^>]*role="tab"[^>]*aria-selected="false"[^>]*tabindex="-1"[^>]*>Reset elector<\/button>/);
    expect(html).toContain('role="tabpanel" id="panel-turnout" aria-labelledby="tab-turnout"');
    expect(html).toContain('<h2 tabindex="-1">Turnout</h2>');
    expect(html).not.toContain("Audit log");
  });

  it("SR-05: an auditor gets Turnout, Audit log and Verify chain", () => {
    const html = renderToStaticMarkup(<StaffConsole role="auditor" onSessionEnded={noop} />);

    expect([...html.matchAll(/role="tab"[^>]*>([^<]+)</g)].map((match) => match[1])).toEqual(["Turnout", "Audit log", "Verify chain"]);
    expect(html).not.toContain("Reset elector");
  });

  it("SR-05: an elector account gets no staff functions", () => {
    const html = renderToStaticMarkup(<StaffConsole role="elector" onSessionEnded={noop} />);

    expect(html).toBe("<p>This account has no staff functions.</p>");
  });

  it("SR-05: Reset starts disabled, with the explanation, a labelled field and an aria-live region", () => {
    const html = renderToStaticMarkup(<ResetPanel state={INITIAL_CONSOLE} dispatch={noop} run={run} />);

    expect(html).toContain(
      "Clears an abandoned ballot for an elector who was issued a ballot but has not voted. A cast ballot can never be reset.",
    );
    expect(html).toContain('<label for="reset-roll-id">Roll ID</label>');
    expect(html).toMatch(/<input type="checkbox"[^>]*\/>/);
    expect(html).toMatch(/<button type="submit" class="btn btn-danger" disabled=""[^>]*>Reset<\/button>/);
    expect(html).toContain('role="status" aria-live="polite"');
  });
});

describe("SR-05: staff console source", () => {
  it("SR-05: nothing is rendered as HTML or run as code", () => {
    const folder = fileURLToPath(new URL(".", import.meta.url));
    const sources = readdirSync(folder).filter((file) => /\.tsx?$/.test(file) && !/\.test\.tsx?$/.test(file));
    const banned = /dangerouslySetInnerHTML|innerHTML|outerHTML|\beval\(|new Function\(/;

    expect(sources).toContain("StaffConsole.tsx");
    for (const file of [...sources.map((name) => join(folder, name)), fileURLToPath(new URL("../api/staffClient.ts", import.meta.url))]) {
      expect(banned.test(readFileSync(file, "utf8")), file).toBe(false);
    }
  });
});
