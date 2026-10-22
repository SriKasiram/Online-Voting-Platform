# SR-09 inspection: no ballot selections left in the browser

SR-09 requires that, once a session ends, inspecting the browser finds no ballot selections. This checklist is that inspection, done by hand in Chrome DevTools. Run it after each of the three ways a session ends: **A** sign-out, **B** timeout, **C** submission. Save each screenshot in [`sr09-evidence/`](sr09-evidence/) under the filename in the table, then fill in the Actual result column.

## Before you start

1. Start the database, backend and frontend as in [MANUAL.md](MANUAL.md), section 4. The reviewer must already be registered.
2. Open a new Chrome window and go to any other page first (for example `https://example.com`), then open http://localhost:5173 in the same tab. The Back button test needs a page to go back to.
3. Press **F12** to open DevTools. In the **Network** tab, tick **Preserve log**. Leave **Disable cache** unticked, so the browser behaves as it would for a voter.
4. Note the surname of one candidate you will number, for example `ORTEGA`. You will search for it after the session ends.

Run the scenarios in this order. Each elector gets one ballot (SR-03): after A and after B, run `python -m scripts.seed --reset-participation` in `backend` (virtual environment active) so the reviewer can be issued a new ballot. C is last because the reviewer has then voted. To repeat C, use `python -m scripts.seed --reset`, which deletes all data.

## The checks

After the session ends, do each check below. In the **Application** tab, select `http://localhost:5173` under each storage heading.

| Check | Where | Expected result |
|---|---|---|
| Local storage | Application > Storage > Local storage | No keys |
| Session storage | Application > Storage > Session storage | No keys |
| IndexedDB | Application > Storage > IndexedDB | No databases |
| Cookies | Application > Storage > Cookies | No `session` cookie (the only cookie the app sets; sign-out deletes it). No other cookie holds ballot data |
| Cache storage | Application > Storage > Cache storage | Empty |
| Page (DOM) | Elements: press Ctrl+F, search for the surname you noted, then for `Number 1` | No match. The page shows only the sign-in screen |
| `/api/ballot` headers | Network: select the `ballot` request > Headers > Response headers | `Cache-Control: no-store` and `Pragma: no-cache` |
| `/api/ballot/submit` headers (C only) | Network: select the `submit` request > Headers > Response headers | `Cache-Control: no-store` and `Pragma: no-cache` |
| Back button | Press Back (you leave the app, which adds no history entries of its own), then Forward | The app reloads at the sign-in screen with no ballot. Optional: Application > Background services > Back/forward cache > **Test back/forward cache** shows whether Chrome kept the page; either way the result must be the sign-in screen |

## Scenario A: after sign-out

1. Sign in as the reviewer. Number every box, select **Review ballot**, then **Change ballot** and **Review ballot** again. The ranking must still be there.
2. Select **Sign out** in the top bar, without submitting.
3. Do the checks and record them below.

## Scenario B: after a timeout

1. Sign in and number some boxes.
2. Wait for the session to end without selecting **Keep voting** (10 minutes). The sign-in screen then says your session ended. To wait less, set `SESSION_MINUTES=2` in `backend/.env` and `VITE_SESSION_MINUTES=2` in `frontend/.env`, restart both, and put both back afterwards. Never commit either file.
3. Do the checks and record them below.

## Scenario C: after a successful submission

1. Sign in, number every box, review, tick the confirm box and select **Submit ballot**.
2. On the receipt screen, search Elements for the surname you noted. Expected: no match, because the receipt shows only the receipt code, the time accepted, the election and the division.
3. Select **Finish and sign out** (or wait 60 seconds).
4. Do the checks, including the `submit` request headers, and record them below.

## Results

Tester: ______________  Date: ______________  Chrome version (chrome://version): ______________

| # | Item | Expected result | Actual result | Screenshot filename |
|---|---|---|---|---|
| A1 | Local storage after sign-out | No keys | | `A1-local-storage.png` |
| A2 | Session storage after sign-out | No keys | | `A2-session-storage.png` |
| A3 | IndexedDB after sign-out | No databases | | `A3-indexeddb.png` |
| A4 | Cookies after sign-out | No `session` cookie | | `A4-cookies.png` |
| A5 | Cache storage after sign-out | Empty | | `A5-cache-storage.png` |
| A6 | Page after sign-out | Sign-in screen only, no candidate name or number | | `A6-elements.png` |
| A7 | `/api/ballot` response headers | `Cache-Control: no-store`, `Pragma: no-cache` | | `A7-ballot-headers.png` |
| A8 | Back, then Forward, after sign-out | Reloads to the sign-in screen | | `A8-back-button.png` |
| B1 | Local storage after timeout | No keys | | `B1-local-storage.png` |
| B2 | Session storage after timeout | No keys | | `B2-session-storage.png` |
| B3 | IndexedDB after timeout | No databases | | `B3-indexeddb.png` |
| B4 | Cookies after timeout | No `session` cookie | | `B4-cookies.png` |
| B5 | Cache storage after timeout | Empty | | `B5-cache-storage.png` |
| B6 | Page after timeout | Sign-in screen with the "session ended" notice only | | `B6-elements.png` |
| B7 | `/api/ballot` response headers | `Cache-Control: no-store`, `Pragma: no-cache` | | `B7-ballot-headers.png` |
| B8 | Back, then Forward, after timeout | Reloads to the sign-in screen | | `B8-back-button.png` |
| C1 | Receipt screen | Receipt code, time, election and division only; no candidate name | | `C1-receipt.png` |
| C2 | Local storage after submission and sign-out | No keys | | `C2-local-storage.png` |
| C3 | Session storage after submission and sign-out | No keys | | `C3-session-storage.png` |
| C4 | IndexedDB after submission and sign-out | No databases | | `C4-indexeddb.png` |
| C5 | Cookies after submission and sign-out | No `session` cookie | | `C5-cookies.png` |
| C6 | Cache storage after submission and sign-out | Empty | | `C6-cache-storage.png` |
| C7 | Page after submission and sign-out | Sign-in screen only, no candidate name or number | | `C7-elements.png` |
| C8 | `/api/ballot/submit` response headers | `Cache-Control: no-store`, `Pragma: no-cache` | | `C8-submit-headers.png` |
| C9 | Back, then Forward, after submission and sign-out | Reloads to the sign-in screen | | `C9-back-button.png` |

Any result that differs from the expected one fails SR-09. Note what was found and where.
