import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import IdleWarning from "./IdleWarning";
import SessionWarning from "./SessionWarning";

// SR-04, SR-15: both warnings now render through the shared WarningDialog; their markup is unchanged
const noop = () => undefined;

describe("SR-04, SR-15: the shared warning dialog", () => {
  it("SR-04: the session warning is a labelled dialog with its two buttons and texts", () => {
    const html = renderToStaticMarkup(<SessionWarning open={false} secondsLeft={59} minutes={10} canExtend onKeep={noop} onSignOut={noop} />);

    expect(html).toMatch(/^<dialog class="idle" aria-labelledby="session-warning-title" aria-describedby="session-warning-desc">/);
    expect(html).toContain('<h2 id="session-warning-title">Do you need more time?</h2>');
    expect(html).toContain("Your session ends in <strong class=\"mono\">0:59</strong>. Select Keep voting to get another 10 minutes.");
    expect(html).toContain(">Sign out now</button>");
    expect(html).toContain(">Keep voting</button>");
  });

  it("SR-04: after the last extension the warning says so and offers Continue", () => {
    const html = renderToStaticMarkup(<SessionWarning open={false} secondsLeft={5} minutes={10} canExtend={false} onKeep={noop} onSignOut={noop} />);

    expect(html).toContain('<h2 id="session-warning-title">Your session cannot be extended again</h2>');
    expect(html).toContain(">Continue</button>");
  });

  it("SR-15: the idle warning is an alertdialog with one button", () => {
    const html = renderToStaticMarkup(<IdleWarning open={false} secondsLeft={1} onStillHere={noop} />);

    expect(html).toMatch(/^<dialog class="idle" role="alertdialog" aria-labelledby="idle-warning-title" aria-describedby="idle-warning-desc">/);
    expect(html).toContain('<h2 id="idle-warning-title">Are you still there?</h2>');
    expect(html).toContain('This session will end in <strong class="mono">1</strong> second to protect your vote.');
    expect(html.match(/<button/g)).toHaveLength(1);
  });
});
