# Electronic Voting Platform Prototype

Prototype for the Electronic Voting Platform group assignment. It covers the House of Representatives voting flow only. Senate voting and overseas voting are design only.

Stack: React with TypeScript (Vite), FastAPI (Python 3.12, SQLAlchemy 2.0, Alembic), PostgreSQL 16.

New to the project? [docs/MANUAL.md](docs/MANUAL.md) lists every file and shows how to start, reset and stop the app.

## Status

| Part | State |
|---|---|
| `frontend/` | Register, two-part sign in, tap-to-rank ballot, review and receipt screens. All data comes from the backend |
| `backend/` | Registration for people on the electoral roll, sign in with a password and an authenticator app, the ballot and submission. Stored ballots are AES-256-GCM encrypted (SR-11); ballot signing comes in a later stage |
| `docker-compose.yml` | PostgreSQL 16 for local development |

The backend serves the API and the built frontend together, over HTTPS only (TLS 1.3, SR-10), at https://localhost:8443. There is no plaintext address.

```
Browser -> https://localhost:8443 (TLS 1.3) -> FastAPI: /api and the built frontend -> PostgreSQL (5432)
```

## Run the app

You need Docker (for PostgreSQL), Python 3.12 and Node 22 or newer. Start from the repository root.

### 1. Settings

```
cp backend/.env.example backend/.env           # macOS / Linux
Copy-Item backend\.env.example backend\.env    # Windows PowerShell
```

Open `backend/.env` and set two values:

- `POSTGRES_PASSWORD`: a long random value. Do this before step 2: PostgreSQL stores the password the first time the database starts and ignores later changes to `.env`. If you see `password authentication failed for user "evoting"`, the two have drifted apart (see step 2).
- `HSTS_MAX_AGE=300` and `COOKIE_SECURE=true` come from `.env.example` (SR-10). If your `.env` is older, add `HSTS_MAX_AGE=300` and set `COOKIE_SECURE=true`. Without `HSTS_MAX_AGE` the browser is told to use HTTPS for `localhost` for a whole year (see [SR-10](#sr-10-tls-13-for-ballot-transmission)).
- `SECRET_KEY`: at least 32 random characters, for example from `python -c "import secrets; print(secrets.token_urlsafe(48))"`. It protects the encrypted personal data and the enrolment codes. If you change it later, reseed (`python -m scripts.seed --reset`), because data written with the old key can no longer be read.

### 2. Start PostgreSQL

```
docker compose up -d db
```

The data is kept in a Docker volume between restarts. `docker compose down` stops the database and `docker compose down -v` also deletes its data. PostgreSQL only reads the password when it first creates the volume, so if you change `POSTGRES_PASSWORD` later, run `docker compose down -v` and start it again.

If port 5432 is already taken (for example by PostgreSQL installed on your computer), set `POSTGRES_PORT=5433` in `backend/.env` and start the database with `docker compose --env-file backend/.env up -d db`.

### 3. Install the Python packages

```
cd backend
python3.12 -m venv .venv          # Windows: py -3.12 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The remaining commands run inside `backend/` with the virtual environment active.

### 4. Create the tables and load the seed data

```
alembic upgrade head
python -m scripts.seed
```

This adds one open House of Representatives election, three Victorian divisions (Melbourne, Kooyong and Macnamara) with 4 to 6 candidates each, and one electoral roll entry for a reviewer (see [Registering as a reviewer](#registering-as-a-reviewer)). There are no accounts: everyone registers through the app. Running the script again duplicates nothing and gives the reviewer's enrolment code a fresh one-year expiry.

`python -m scripts.seed --reset` deletes all data, including every vote cast, and loads the seed data again. Use it if your database was created before registration existed: older demo accounts can no longer sign in.

Every seed run ends by signing the electoral roll (SR-02), and the first run creates development keys in `backend/keys/`. The API will not start until the roll is signed. If your database existed before SR-02, run `alembic upgrade head` and then `python -m scripts.sign_roll` (or reseed).

The seed also stores version 1 of the election's ballot definition, signed by two development delegates (SR-07). The API will not start while an open election has no valid definition. If your database existed before SR-07, run `alembic upgrade head` and then `python -m scripts.seed`.

**After the SR-11 migration the old test ballots are gone.** If your database existed before SR-11, `alembic upgrade head` discards its plaintext test ballots, together with their receipts and "voted" marks. Assumption: the prototype database contains only seed and test data; old plaintext test ballots are discarded and must be recreated by re-running the seed script and casting new test ballots. So run `python -m scripts.seed` again, then cast new test ballots.

### 5. Create the ballot encryption key (once)

```
python -m scripts.gen_ballot_key
```

This creates `backend/keys/ballot.key`: 32 random bytes, the AES-256 key that encrypts every stored ballot (SR-11). The server refuses to start without it. The script never replaces an existing key unless you add `--force`, which makes every ballot already stored unreadable.

> **Back up the key, and never commit it.** Keep a copy somewhere safe and separate from the database and its backups. If the key is lost, every stored ballot is unreadable and nobody can recover them. `backend/keys/` is in `.gitignore`. Never email it or put it in shared documents.

SR-13: also create the ballot chain's checkpoint keys, `python -m scripts.gen_checkpoint_key`. They are needed only to seal and verify; the server starts without them.

### 6. Build the frontend

```
cd ../frontend
npm ci
npm run build
cd ../backend
```

This writes `frontend/dist`, the voter app and `staff.html`, which the backend serves. Build again after changing the frontend.

### 7. Create and trust the development certificate (once)

```
python -m scripts.dev_certs
```

This creates `certs/dev-cert.pem` and `certs/dev-key.pem` at the project root: one self-signed certificate for `localhost` and `127.0.0.1`, valid for 365 days. `certs/` is never committed. The script will not replace existing files unless you add `--force`.

Then trust `certs/dev-cert.pem` once, so the browser accepts it. Run the command for your system from the project root (the script prints the same commands):

| System | Command |
|---|---|
| Windows | `certutil -user -addstore Root certs\dev-cert.pem`, confirm the prompt, then restart the browser |
| macOS | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db certs/dev-cert.pem` |
| Linux | Chrome: `certutil -d sql:$HOME/.pki/nssdb -A -t "P,," -n evoting-dev -i certs/dev-cert.pem` (package `libnss3-tools`). System-wide: copy it to `/usr/local/share/ca-certificates/evoting-dev.crt` and run `sudo update-ca-certificates` |

Use Chrome or Edge. If the browser shows a certificate warning, the certificate is not trusted yet: never click through it. A certificate made again with `--force` must be trusted again.

### 8. Start the server

```
python -m app.serve
```

Open https://localhost:8443. To vote, register first (see [Registering as a reviewer](#registering-as-a-reviewer)), then sign in.

- https://localhost:8443/staff.html is the staff sign-in page (SR-06)
- https://localhost:8443/api/health returns `{"status": "ok"}`
- https://localhost:8443/api/divisions lists the divisions stored in the database
- https://localhost:8443/docs lists every endpoint and lets you try them

The server refuses to start without the certificate and key, and never falls back to plain HTTP. It also refuses without a usable ballot key (SR-11). It does not reload on code changes: stop it with Ctrl+C and start it again.

### 9. Run the tests

```
pytest
```

PostgreSQL must be running. Every run deletes and rebuilds a separate `evoting_test` database from the migrations. The tests create their own data and never rely on the seed, so your development data is never touched.

## Vite dev server (development only)

For working on the frontend. `npm run dev` serves the app over **plain HTTP** at http://localhost:5173 with live reload, and forwards `/api` to https://localhost:8443, checking the backend's certificate. It is a development tool only: the ballot casting demo always uses https://localhost:8443. Start the backend first, then inside `frontend/`:

```
NODE_EXTRA_CA_CERTS=../certs/dev-cert.pem npm run dev              # macOS / Linux
$env:NODE_EXTRA_CA_CERTS = "..\certs\dev-cert.pem"; npm run dev    # Windows PowerShell
```

Without `NODE_EXTRA_CA_CERTS` the proxy rejects the self-signed certificate and every `/api` call fails. After you have opened https://localhost:8443, the browser may switch http://localhost:5173 to HTTPS for `HSTS_MAX_AGE` seconds (see [SR-10](#sr-10-tls-13-for-ballot-transmission)).

## Registering as a reviewer

Only people on the electoral roll can register. The seed script puts one person on the roll for you to register as. **Every detail below is fake test data.** The enrolment code is written here only because this is a prototype. In a real deployment, each voter's code would reach them by post or email, and nothing in the app ever shows one.

| Field | Enter |
|---|---|
| Given name | `Robin` |
| Surname | `Reviewer` |
| Date of birth | `1 January 1990` (1990-01-01) |
| Postcode | `3000` |
| Enrolment code | `RVWR-7K3M-Q9TX` |

You also need an authenticator app on your phone, such as Google Authenticator or Microsoft Authenticator.

1. On the sign-in screen, select **Register to vote** and enter the details above. Letter case, extra spaces and the code's hyphens do not matter. Any mistake gets the same message, so the screen never reveals who is on the roll.
2. Choose a username (3 to 32 letters, digits, dots or underscores) and a password of at least 12 characters.
3. Scan the QR code with your authenticator app, or type the setup key it shows, then enter the 6-digit code from the app.

Registration then returns to the sign-in screen. Sign in with your username, password and a fresh code from the app. The reviewer's roll entry is in the Melbourne division.

The enrolment code works once. To register again, for example to repeat the review, run this in `backend/`:

```
python -m scripts.seed --reset-reviewer
```

It deletes the reviewer's account, clears the registration and wrong-code count, and restores the code with a fresh one-year expiry. A ballot already cast stays in the ballot box: ballots are not linked to voters, so it cannot be found and removed. The reviewer's participation record stays too (SR-03), so a reviewer who has voted cannot vote again; only `python -m scripts.seed --reset` starts that over. If the reviewer was issued a ballot but lost it, for example by reloading the page, `python -m scripts.seed --reset-participation` lets them be issued a new one (see [SR-03](#sr-03-single-ballot-per-elector)).

After 5 wrong enrolment codes the entry is locked, and the same reset unlocks it. A registration must be finished within 10 minutes of step 1.

## API

| Request | Purpose |
|---|---|
| `GET /api/health` | Liveness check |
| `GET /api/divisions` | Divisions stored in the database |
| `POST /api/register/verify` | Registration, step 1: given name, surname, date of birth, postcode and enrolment code. Every failure answers `400 registration_failed` |
| `POST /api/register/account` | Step 2: username and password. Returns the authenticator setup link and key, once, with `Cache-Control: no-store` |
| `POST /api/register/confirm` | Step 3: a code from the authenticator app. Creates the account |
| `POST /api/auth/login` | Sign in, part 1: username and password. `204` and a session cookie that only allows part 2. Every failure answers `401 invalid_credentials` (SR-01) |
| `POST /api/auth/verify` | Part 2: the code from the authenticator app. Replaces the session with a new signed-in one and returns the voter's name (SR-01) |
| `POST /api/auth/extend` | Starts a new full session under a new identifier, at most twice per sign in (SR-04). Called only when the voter chooses Keep voting |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/ballot` | The voter's ballot paper, taken only from the verified signed definition (SR-07), and a single-use ballot token, once per election (SR-03) |
| `POST /api/ballot/submit` | Accepts the ranked ballot once and, after the commit, returns a 128-bit receipt reference (SR-14). The same token again returns the same reference (SR-03). An informal or invalid ranking gets 422 and can be corrected (SR-08). A database wait over `ACCEPT_TIMEOUT_SECONDS` gets `503 try_again` and stores nothing (SR-14) |
| `GET /api/admin/turnout` | Staff (SR-05): electors issued a ballot and electors who voted, per division and in total. Permission `turnout:read` |
| `POST /api/admin/electors/{roll_id}/reset` | Staff (SR-05): clears an elector's issued ballot, never a vote. Permission `elector:reset` |
| `GET /api/admin/audit-log` | Staff (SR-05): audit entries in order, `limit` (at most 200) and `offset`. Permission `audit:read` |
| `GET /api/admin/audit-log/verify` | Staff (SR-05): recomputes the audit hash chain. Permission `audit:verify` |

Errors come back as `{"detail": "<reason>"}`:

- Sign in and voting: `invalid_credentials` and `not_signed_in` (401), `too_many_requests` (429), `forbidden` (staff, SR-05) and `not_enrolled` (403), `no_open_election` (404), `already_voted` and `extension_limit` (409), `invalid_ballot` (400 for a ballot token problem; SR-12 removed `ballot_expired`), `informal_ballot` and `invalid_ballot` (422 for the ranking, SR-08), `ballot_unavailable` (503, SR-07), `try_again` (503, SR-14: nothing was stored, so the same token works again).
- Admin (SR-05): `not_signed_in` (401), `forbidden` (403), `not_found` (404), `already_voted` (409).
- Registration: `registration_failed`, `username_invalid`, `password_too_short`, `password_is_username`, `wrong_code` and `too_many_attempts` (400), `registration_session_invalid` (401), `username_taken` and `already_registered` (409).

## Checks

Frontend, inside `frontend/`:

```
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

Backend, inside `backend/` with PostgreSQL running:

```
pytest
```

The same checks run on every pull request through GitHub Actions (`.github/workflows/ci.yml`). The backend job runs pytest against a PostgreSQL 16 service container.

Before every release, also run the SR-11 storage audit, `python -m scripts.audit_ballots`, against the release database. It must exit with code 0. See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).

Before each election, export the ballot side (`python -m scripts.export_ballots`) and take backups as two separate dump files, one for each side ([SR-12](#sr-12-identity-and-ballots-kept-apart)). Then run `python -m scripts.audit_separation --file <each backup and export file>`. It must also exit with code 0. Finally run `python -m scripts.verify_chain --election <id>` for each election ([SR-13](#sr-13-integrity-protected-ballot-storage)): it must exit with code 0, and its head hash goes in the release record.

## Settings

### Frontend

Optional. The defaults work as they are. To change them, copy `frontend/.env.example` to `frontend/.env`.

| Variable | Purpose | Default |
|---|---|---|
| `VITE_SESSION_MINUTES` | Length of a voting session. The voter is warned 1 minute before it ends. Keep it equal to `SESSION_MINUTES` | `10` |
| `VITE_API_TARGET` | Where the dev server forwards `/api` requests (SR-10: HTTPS) | `https://localhost:8443` |
| `VITE_IDLE_SECONDS`, `VITE_IDLE_WARNING_SECONDS` | SR-15: seconds without input before "Are you still there?", and how long that warning stays before the reset. See [SR-15](#sr-15-ending-finished-and-abandoned-sessions) | `90`, `30` |
| `VITE_RECEIPT_SECONDS` | SR-15: seconds the receipt screen stays. Keep it equal to the backend's `POST_BALLOT_SESSION_SECONDS` | `60` |
| `VITE_RESET_LOGOUT_TIMEOUT_MS` | SR-15: how long the reset waits for the logout request (500 to 3000) | `3000` |

### Backend

Copy `backend/.env.example` to `backend/.env`. Docker Compose reads the same file to create the database.

| Variable | Purpose | Default |
|---|---|---|
| `POSTGRES_USER` | Database user | `evoting` |
| `POSTGRES_PASSWORD` | Database password. Required: the API will not start without it | none |
| `POSTGRES_DB` | Development database | `evoting` |
| `POSTGRES_HOST` | Database host. Use `127.0.0.1`, not `localhost`, which stalls on Windows | `127.0.0.1` |
| `POSTGRES_PORT` | Database port | `5432` |
| `POSTGRES_TEST_DB` | Database that pytest rebuilds on every run. Must end in `_test` | `evoting_test` |
| `SESSION_MINUTES` | How long a signed-in session lasts, fixed from issue. Keep it equal to `VITE_SESSION_MINUTES` | `10` |
| `MAX_SESSION_EXTENSIONS`, `POST_BALLOT_SESSION_SECONDS` | Extensions allowed per sign in, and how long a session survives once its ballot is accepted. See [SR-04](#sr-04-session-lifetime-and-binding) | `2`, `60` |
| `ACCEPT_TIMEOUT_SECONDS` | SR-14: seconds any lock wait or statement in the ballot accept transaction may take before the voter gets `503 try_again`. 1 to 9. See [SR-14](#sr-14-ballot-acceptance-confirmation) | `8` |
| `SECRET_KEY` | Root secret for field encryption and keyed hashes, at least 32 characters. Required | none |
| `MAX_FAILED_ATTEMPTS`, `LOCK_MINUTES`, `MFA_PENDING_MINUTES`, `RATE_LIMIT_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS`, `COOKIE_SECURE` | Sign-in lockout, rate limit and cookie settings. See [SR-01](#sr-01-authentication-and-rate-limiting) | `5`, `15`, `2`, `20`, `300`, `true` |
| `ROLL_PUBLIC_KEY_PATH`, `MIN_VOTING_AGE` | The roll's Ed25519 public key, and the minimum age on polling day. See [SR-02](#sr-02-roll-signing-and-eligibility) | `backend/keys/roll_public.pem`, `18` |
| `DELEGATE_KEYRING_PATH`, `REQUIRED_DELEGATE_APPROVALS`, `MIN_ACTIVATION_LEAD_HOURS` | The delegates' public keyring, the distinct delegates who must sign, and how long before polls open a definition must be activated. See [SR-07](#sr-07-signed-ballot-definitions) | `backend/keys/delegates/keyring.json`, `2`, `24` |
| `MIN_SEAL_BATCH`, `CHECKPOINT_DIR` | SR-13: the smallest batch sealed without `--final`, and the folder of signed checkpoints (relative to `backend/`). See [SR-13](#sr-13-integrity-protected-ballot-storage) | `10`, `checkpoints` |
| `CHECKPOINT_PUBLIC_KEY`, `CHECKPOINT_PRIVATE_KEY` | SR-13: the checkpoint key pair (`python -m scripts.gen_checkpoint_key`). The private key is for the seal script only | `keys/checkpoint_public.pem`, `keys/checkpoint_private.pem` |
| `LOG_DIR` | Folder of the server's log files, if its output is saved to files. The SR-12 separation audit scans it | `logs/` at the project root |
| `BALLOT_KEY_FILE` | The 32-byte AES-256 key that encrypts every stored ballot (`python -m scripts.gen_ballot_key`). No default key exists: without this file the API does not start. See [SR-11](#sr-11-ballots-encrypted-at-rest) | `backend/keys/ballot.key` |
| `HSTS_MAX_AGE` | Seconds the browser must use HTTPS only for this host. `.env.example` sets `300` for local work. See [SR-10](#sr-10-tls-13-for-ballot-transmission) | `31536000` (one year) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE`, `SERVER_PORT` | The TLS certificate and key `python -m app.serve` uses (relative to the project root), and its single HTTPS port (SR-10) | `certs/dev-cert.pem`, `certs/dev-key.pem`, `8443` |

The fixed limits (registration time, wrong-code limits, rate limits, password length) are named constants in `backend/app/config.py`.

Never commit a real `.env` file. Only `.env.example` belongs in Git.

## Frontend security notes

- The browser never decides anything that matters. The rules in `src/lib/ballotRules.ts` and `src/lib/registerRules.ts` only give quick feedback, and the server repeats every check.
- Nothing is stored in `localStorage` or `sessionStorage`. The ballot token, selections and registration details live in memory and are cleared on submit, sign out, session timeout and leaving the register screen. SR-09 adds a lost session and leaving the page, and a test that enforces it (see [SR-09](#sr-09-client-side-data-handling)).
- Sign in and registration step 1 each show one generic message for every failure, so the screen never reveals which detail was wrong, or who is on the roll.
- Passwords are cleared from the page as soon as they are sent. The authenticator secret and QR code exist only while step 3 is on screen.
- The session timer counts down from sign in. Ordinary activity does not reset it. Only the voter choosing Keep voting in the warning calls `POST /api/auth/extend`, and only that call extends the server session. The timer restarts only once the server agrees. After the second extension the warning says no more time is available, and the session ends on time (SR-04).
- Finishing or leaving a session resets the screen within 5 seconds: Done or 60 seconds on the receipt screen, 120 seconds without input, sign out, session end or a lost session. The start page is then loaded afresh (see [SR-15](#sr-15-ending-finished-and-abandoned-sessions)).
- Fonts are bundled with the app (no font CDN), and the QR code is drawn in the browser, so the page makes no third-party requests.
- Sessions live in `HttpOnly`, `SameSite=Strict` cookies, so page scripts cannot read them and other sites cannot send them. The frontend and API are served from one origin, https://localhost:8443 (SR-10).

## Backend security notes

- Voter identity (`electoral_roll`, `accounts`, `sessions`, `registration_sessions`, `voter_participation`) is kept apart from the anonymous ballot box (`ballot_tokens`, `ballots`). The ballot tables have no account or roll column, ballots have no timestamp, and ballot ids are random UUIDs. `tests/test_ballot_secrecy.py` fails if anyone adds a column to those tables.
- `voter_participation` records that an elector was issued a ballot or voted, never how. Its primary key `(roll_id, election_id)` makes the database refuse a second record. Submitting consumes the ballot token, stores the ballot and marks the elector voted in one transaction, so a vote is never half recorded (SR-03).
- Personal data on the roll (name, address, date of birth, postcode) and every authenticator secret are encrypted with AES-256-GCM, bound to their column. Registration finds a roll entry through a blind index (a keyed hash of the normalised name, date of birth and postcode), so nothing is decrypted to search.
- Passwords are hashed with Argon2id. Enrolment codes are stored as keyed hashes and compared in constant time. Session, sign-in, registration and ballot tokens are stored only as SHA-256 hashes.
- All keys are derived from `SECRET_KEY` with HKDF, one per purpose.
- Registration step 1 answers every failure identically and does the same hashing work either way. It is rate limited per client IP and per roll entry, and 5 wrong enrolment codes lock the entry's code. Step 3 allows 5 wrong authenticator codes before the registration ends.
- Two registrations for the same person cannot both succeed: step 1 locks the roll entry row while it spends the code, step 3 sets `registered_at` only if it is still empty, and `accounts.roll_id` is unique.
- The audit log records `REGISTRATION_STARTED`, `REGISTRATION_COMPLETED` and `REGISTRATION_FAILED`, and the sign-in events listed under SR-01 below. Each entry is chained to the previous one by a SHA-256 hash. Entries hold only the roll entry id, or the client IP when nothing matched: never names, dates of birth, postcodes, codes or secrets.

### Limitations, for later stages

- Ballots are now stored AES-256-GCM encrypted (SR-11), and ballot definitions are signed (SR-07). The ballot key sits on the same machine as the database (see SR-11's limits).
- A ballot holds no voter and no time, but it is stored in the same transaction that marks the voter. Someone with direct access to the database could match the two through PostgreSQL's internal transaction ids. A later stage should store ballots separately or in shuffled batches.
- The rate limiter keeps its counts in memory, so they reset when the API restarts and are not shared between several API processes. Behind the dev server's proxy every request comes from `127.0.0.1`, so the per-IP limit counts all users together.
- There is no CSRF token yet. `SameSite=Strict` cookies are the only protection. The session cookie is marked `Secure` (SR-10: `.env.example` now sets `COOKIE_SECURE=true`). The registration cookie is not marked `Secure` yet, although it now travels only over TLS (SR-10).
- Docker Compose passes all of `backend/.env` into the database container, including `SECRET_KEY`, which the database does not need.
- The receipt reference is derived from the ballot token, and only its hash is stored, on the used token row (SR-14). There is no way for a voter to check it yet.

## SR-01: authentication and rate limiting

Every elector must pass two steps before any voting route opens:

1. `POST /api/auth/login`: the password is checked against its Argon2id hash. Success starts a session at stage `mfa_pending`, which lasts `MFA_PENDING_MINUTES` and opens nothing except step 2.
2. `POST /api/auth/verify`: a 6-digit TOTP code from the authenticator app, from the current 30-second step or one either side. Each step's code works once. Success deletes the pending session and starts a new `authenticated` session under a new token.

`GET /api/ballot`, `POST /api/ballot/submit` and `POST /api/auth/extend` accept only an unexpired `authenticated` session. A pending session gets `401`.

| Setting | Default | Effect |
|---|---|---|
| `MAX_FAILED_ATTEMPTS` | `5` | Failed attempts in a row, at either step, before the account locks. A full sign in resets the count |
| `LOCK_MINUTES` | `15` | How long the account stays locked. The count starts again once the lock ends |
| `MFA_PENDING_MINUTES` | `2` | Time allowed between step 1 and step 2 (5 before SR-04) |
| `RATE_LIMIT_ATTEMPTS` | `20` | Sign-in requests (both steps together) allowed per client IP in each window |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | Length of that window |
| `COOKIE_SECURE` | `true` | Marks the `session` cookie `Secure`. SR-10: the app runs only over HTTPS, so `backend/.env.example` sets it to `true` as well |

Responses:

- `401 {"detail": "invalid_credentials"}`: a wrong password, an unknown username, a wrong or reused code, an expired pending session or a locked account. The status and body are identical in every case, and an unknown username or a locked account still runs an Argon2id check against a dummy hash, so the timing reveals nothing either.
- `429 {"detail": "too_many_requests"}`: the client IP has used up `RATE_LIMIT_ATTEMPTS` in the current window. The address is the connecting one; `X-Forwarded-For` is ignored.

Other details:

- Failures are counted in a single `UPDATE`, so attempts sent at the same time are all counted. When the account locks, any session waiting for its code is deleted.
- The cookie is `session`: `HttpOnly`, `SameSite=Strict`, `Path=/`, with no `Max-Age`. The expiry stored on the server decides when a session ends. Only the SHA-256 of the cookie value is stored. Logging out deletes the session row and clears the cookie.
- The audit log records `auth_password_failed`, `auth_totp_failed`, `auth_account_locked`, `auth_rate_limited` and `auth_login_success`, with only the account (`account:<id>`, or `unknown`) and the event type. No passwords, codes, secrets or tokens.

Run the SR-01 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr01_auth.py -v
```

Design only, not implemented:

- Escalating locks, where each further lock lasts longer.
- A shared rate-limit store such as Redis. Counts are kept in memory, so they reset when the API restarts and are not shared between API processes.
- Passkeys (WebAuthn) as a phishing-resistant alternative to passwords and TOTP.

## SR-02: roll signing and eligibility

Every electoral roll record carries an Ed25519 signature, and a ballot is issued, or accepted, only to a voter whose record checks out.

**What is signed.** Only the fixed eligibility fields: the record id, the identity blind index (`roll_lookup`), the date of birth (ISO date), the enrolment status and the division. Nothing that registration or voting changes later (`registered_at`, the enrolment code and its attempts) is signed, so those changes never break a signature. The signed message is the tag `evoting-roll-record-v1`, a newline, and compact UTF-8 JSON of those fields with sorted keys (`app/roll_signing.py`).

**Keys and signing.** The API holds only the public key (`ROLL_PUBLIC_KEY_PATH`, default `backend/keys/roll_public.pem`). The private key is `backend/keys/roll_private.pem`, and Git ignores the whole folder. To create the keys and sign every record:

```
python -m scripts.sign_roll
```

The first run creates a development key pair. Later runs reuse it. `python -m scripts.seed` signs the roll as its last step. Nothing under `app/` imports the signing script or reads the private key, and a test checks this.

**Start-up check.** When the API starts it verifies every record. If the public key is missing, or any record fails, it logs how many failed (never names or dates of birth), writes `ROLL_VERIFICATION_FAILED` to the audit log and refuses to start. There is no setting to skip this. A record added or changed without the private key is caught here. A deleted record is not, but it fails safe: that voter is then refused a ballot.

**Before every ballot**, and again when a ballot is submitted, `app/eligibility.py` checks in order:

1. the voter's roll record exists;
2. its signature is valid;
3. they are enrolled;
4. they have a division;
5. they are at least `MIN_VOTING_AGE` (18) on the election's polling date.

The ballot is the one for the division in the verified record. Any division the browser sends, in the query, a header or the body, is ignored.

**Age rule.** Age is counted on the election's polling date (`elections.polling_date`), not on the day the voter votes: `polling.year - born.year - ((polling.month, polling.day) < (born.month, born.day))`. Someone born on 29 February is therefore treated as born on 1 March in years without a 29 February: still 17 on 28 February of the year they turn 18, and 18 on 1 March. A record with no readable date of birth is refused.

**Errors.** Every refusal answers `403 {"detail": "not_enrolled"}`, which the frontend already shows as "You are not enrolled to vote in this election". A failed signature, therefore, looks exactly like not being enrolled. The audit log records `ELIGIBILITY_DENIED` with the account and a reason: `no_record`, `bad_signature`, `not_enrolled`, `no_division` or `under_age`. A successful start-up records `ROLL_VERIFIED` with the number of records.

Run the SR-02 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr02_eligibility.py -v
```

Design only, not implemented:

- A signed manifest of the whole roll, which would also catch deleted records.
- Approval of roll changes by two distinct delegate signatures.
- Workflows for changing the eligibility rules or division boundaries.
- Role restrictions and admin approval screens for roll changes.

## SR-03: single ballot per elector

No elector can have more than one ballot accepted in an election, however many requests, devices or replays there are.

**Issue** (`GET /api/ballot`). First the SR-01 signed-in session, then the SR-02 eligibility check. Then, in one transaction, the elector's row is inserted into `voter_participation` with state `issued` (`INSERT ... ON CONFLICT DO NOTHING`). If the row already exists, the elector already has a token or has voted: the answer is `409 already_voted` and nothing is issued. Otherwise the server creates a token of 256 random bits (`secrets.token_urlsafe(32)`), stores only its SHA-256 (hex), and returns the token once in `ballot_token`. SR-12: no expiry is stored; the token is usable while the election is open and the elector is signed in. The token itself is never stored or logged.

**Accept** (`POST /api/ballot/submit`). Again, the signed-in session and eligibility come first. Then, in one transaction:

1. lock the elector's participation row (`SELECT ... FOR UPDATE`), then the token row, always in that order;
2. reject an unknown or altered token (`400 invalid_ballot`);
3. if the token was already used, return the first answer again (`200`, same receipt reference) and store nothing;
4. (SR-12: there is no separate token expiry any more; a closed election gives `404 no_open_election`, and an ended session `401 not_signed_in`);
5. reject an elector who is not `issued`: `409 already_voted` if they have voted, `400 invalid_ballot` if they were never issued a ballot;
6. check the ballot content as before;
7. consume the token with one conditional `UPDATE` that must change exactly one row, recording the SHA-256 of the receipt reference (SR-14; it was a random reference before) and no time (SR-12);
8. store the ballot and mark the elector `voted`, then commit.

Any failure rolls everything back: a token is never used without a ballot, and a ballot never exists without the elector marked voted. A token stays unused after a rejected ballot, so the voter can correct it and submit again.

**Reloading the ballot page loses the token.** The token is returned once and lives only in the page's memory, and a second ballot request gets `already_voted`. The same happens if the session ends before the ballot is submitted. During development, clear the reviewer's `issued` state with:

```
python -m scripts.seed --reset-participation
```

It refuses once the reviewer has voted, because a cast ballot cannot be undone by design. Only `python -m scripts.seed --reset` (all data) starts that over. Each reset is audited as `ELECTOR_RESET`. There is no API endpoint or staff screen for it.

**Unlinked tables.** `voter_participation` (roll entry, election, state) has no timestamp. `ballot_tokens` (id, election, hash, used flag, receipt hash) has no elector and no time at all (SR-12, SR-14). `ballots` (id, election, division, content) has no token, no reference and no time. So the database cannot match a ballot to a token, or a token to an elector. The receipt hash on the used token row is the only handle, and it points at no ballot.

**Audit.** `BALLOT_TOKEN_ISSUED`, `BALLOT_ACCEPTED`, `BALLOT_REPLAY_BLOCKED`, and `BALLOT_TOKEN_REJECTED` with a reason (`invalid`, `wrong_state`; SR-12 removed `expired`), each with the account and the event only. No token, hash, receipt reference, receipt hash (SR-14) or ballot content.

Run the SR-03 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr03_single_ballot.py -v
```

Design only, not implemented:

- Paper and absent-vote channels. They would mark the same `voter_participation` row, so an elector who voted on paper could not vote online, and the reverse.
- Staff screens for resetting an elector.
- Binding the token to the elector. A token works for any eligible elector who holds it, and the participation row still allows only one ballot each.

## SR-04: session lifetime and binding

Sessions live on the server. The cookie holds only a 256-bit random identifier, and the database keeps only its SHA-256.

**Fixed expiry.** A signed-in session expires `SESSION_MINUTES` (10) after it is issued. Activity never lengthens it: requests record `last_seen` but leave `expires_at` alone. Every request checks the expiry, for pending and signed-in sessions alike, and an expired session gets the usual `401`. Expired rows are deleted whenever a new sign in starts.

**Login challenge.** The session between the password step and the code step lasts `MFA_PENDING_MINUTES`, now 2 minutes (it was 5 under SR-01). It is accepted only by `POST /api/auth/verify`, and it is deleted once the code is accepted. The signed-in session that replaces it has a new identifier. A signed-in session is refused by `/auth/verify`, and a pending one by every voting route and `/auth/extend`. The account always comes from the session row, never from anything the browser sends.

**Extension with rotation.** `POST /api/auth/extend` is one `UPDATE`. It gives the session a new identifier, sets its expiry to 10 minutes from now and counts the extension, but only while the session is signed in, unexpired and under `MAX_SESSION_EXTENSIONS` (2).
- The old identifier stops working at once.
- If several requests arrive with the same identifier, only one succeeds; the others get `401`.
- Past the limit the answer is `409 extension_limit`.
- An expired or unknown identifier gets `401`.

Each extension needs an unexpired session, so a sign in lasts at most 30 minutes before the voter must sign in again. In the frontend the timer restarts only after the server agrees. After the limit, the warning says no more time is available and the session ends on time.

**After a ballot.** In the same transaction that accepts the ballot (SR-03), the session's expiry becomes the earlier of its current expiry and `POST_BALLOT_SESSION_SECONDS` (60) from now. Its extensions are also used up. A safe retry of the used token does the same and never lengthens the session. The receipt screen already signs out after 60 seconds.

**Audit.** `SESSION_EXTENDED`, and `SESSION_EXTENSION_REFUSED` with a reason (`limit` or `expired`), each by account only and never with an identifier. Ordinary expired-session rejections are not audited, so they cannot flood the log.

| Setting | Default |
|---|---|
| `SESSION_MINUTES` | `10` |
| `MAX_SESSION_EXTENSIONS` | `2` |
| `MFA_PENDING_MINUTES` | `2` |
| `POST_BALLOT_SESSION_SECONDS` | `60` |

Run the SR-04 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr04_sessions.py -v
```

Design only, not implemented: binding a session to the client's IP address or device. A copied cookie works from anywhere until the session ends, which the fixed 10-minute expiry and the 30-minute cap limit.

## SR-05: role-based access control

Every account has one role, stored in `accounts.role`. On every administrative request the server reads the role from the database, never from the cookie or the session, and checks it against one permission map in `app/rbac.py`.

| Role | Status | Permissions |
|---|---|---|
| `elector` | Implemented. Created only by registration, always with a roll entry | none (the voting routes) |
| `polling_official` | Implemented. Created by `scripts/create_staff.py`, no roll entry | `turnout:read`, `elector:reset` |
| `auditor` | Implemented. Created by `scripts/create_staff.py`, no roll entry | `audit:read`, `audit:verify`, `turnout:read` |
| `returning_officer` | Design only | Dual control for ballot-definition activation, roll replacement and result release |
| `system_administrator` | Design only | Running the platform, with no access to votes or the roll |

The database refuses any other role, an elector without a roll entry, and staff with one.

**Access matrix** (`tests/test_sr05_access_control.py` checks every cell):

| Caller | turnout | reset | audit-log | verify |
|---|---|---|---|---|
| No session, or only the password step done | 401 | 401 | 401 | 401 |
| elector | 403 | 403 | 403 | 403 |
| polling_official | 200 | 200 | 403 | 403 |
| auditor | 200 | 403 | 200 | 200 |

**How the checks work:**
- **Every route checked.** Each `/api/admin` route is declared through `AdminRouter`, which demands a permission and attaches the check.
- **Deny by default.** The API refuses to start if any `/api/admin` route lacks a mapped permission, including one inside an included router. There is no setting to skip this.
- **Denied requests** get `403 {"detail": "forbidden"}` and an `AUTHZ_DENIED` audit entry naming the account and the permission. A caller with no valid session gets the usual `401`, which is not audited.
- **The voting routes** (`/api/ballot`, `/api/ballot/submit`) accept electors only, so staff get `403 forbidden`. Every role can use `/api/auth/logout`. `/api/auth/extend` works for electors; staff sessions cannot be extended (SR-06).

**Create a staff account**, inside `backend/` with the virtual environment active:

```
python -m scripts.create_staff --username official.one --role polling_official
```

The script:
- asks for the password twice, using the same rules as registration (at least 12 characters, not the username);
- stores only its Argon2id hash;
- prints the authenticator setup link and key once;
- refuses a username already in use, or any role other than `polling_official` and `auditor`;
- records `STAFF_CREATED` in the audit log.

No API endpoint creates staff, and the seed creates none.

**Try the admin routes:**
1. Start the server (`python -m app.serve`, SR-10).
2. Open https://localhost:8443/docs.
3. Sign in with `POST /api/auth/login` (username and password), then `POST /api/auth/verify` (the 6-digit code from the authenticator app). In this prototype staff use a TOTP code like electors. The staff sign-in page (SR-06) does the same.
4. Call the `/api/admin` routes from the same page; the browser keeps the session cookie. With curl, keep the cookie in a file:

```
curl --cacert certs/dev-cert.pem -c jar -H "Content-Type: application/json" -d '{"username":"official.one","password":"..."}' https://localhost:8443/api/auth/login
curl --cacert certs/dev-cert.pem -b jar -c jar -H "Content-Type: application/json" -d '{"otp_code":"123456"}' https://localhost:8443/api/auth/verify
curl --cacert certs/dev-cert.pem -b jar https://localhost:8443/api/admin/turnout
```

The reset route uses the same logic as `python -m scripts.seed --reset-participation`, now shared in `app/participation.py`. It clears an `issued` elector (`ELECTOR_RESET`, actor `staff:<account id>`), answers `409 already_voted` for one who has voted and `404 not_found` otherwise.

Run the SR-05 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr05_access_control.py -v
```

Design only, not implemented:

- The `returning_officer` role, with dual control for ballot-definition activation, roll replacement and result release.
- The `system_administrator` role.
- Admin screens. Staff use the API directly.
- An access review before each election and after any staff change.
- Separation of privileged services, and least-privilege database roles.
- Phishing-resistant passkeys (WebAuthn) for staff. SR-06 requires a password and a TOTP code for every staff sign in, but TOTP is not phishing-resistant, and passkeys remain design only.
- Known gap: every `AUTHZ_DENIED` writes an audit row, so a flood of denied requests also floods the log.

## SR-06: multi-factor sign-in for privileged users

Every privileged user (any role except `elector`) signs in with two factors: a password and a 6-digit time-based code (TOTP) from an authenticator app. The admin routes accept only a session that passed both steps; after the password alone they answer `401`. Every SR-01 rule applies to staff exactly as to electors: the generic failure, one use per code, the lockout after 5 failures and the per-IP limit.

| | Electors | Staff |
|---|---|---|
| Sign in | Password, then TOTP code | Password, then TOTP code |
| Session | 10 minutes, extendable twice (SR-04) | 10 minutes, fixed, cannot be extended (`/api/auth/extend` answers `409 extension_limit`) |
| `/api/auth/verify` answers | `{"display_name": ...}` (unchanged) | `{"role": ...}` |
| Audit on success | `auth_login_success` | `auth_login_success` and `AUTH_PRIVILEGED_LOGIN_SUCCESS` |

Every account must have a TOTP secret: `accounts.totp_secret_enc` is `NOT NULL`, and `scripts/create_staff.py` always creates one.

**To sign in as staff:**

1. Create the account, inside `backend/` with the virtual environment active:
   ```
   python -m scripts.create_staff --username official.one --role polling_official
   ```
2. Add the setup link or key it prints, shown only once, to an authenticator app.
3. With the server running (`python -m app.serve`), open https://localhost:8443/staff.html. This page is separate from the voter app.
4. Enter the username and password, then the 6-digit code. The page shows your role and when the session ends, and signs you out after 10 minutes. It does not call any admin route.
5. Use the admin routes from the API docs page (https://localhost:8443/docs) or curl (see SR-05). The docs page is on the same address, so the session cookie works there too.

Run the SR-06 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr06_privileged_mfa.py -v
```

**TOTP is not phishing-resistant.** A fake sign-in page can capture a password and a code and use them within the same 30 seconds.

Design only, not implemented:
- Phishing-resistant passkeys (WebAuthn) for privileged users.
- Re-authentication before each sensitive function.
- A sealed break-glass account, with alerting and a review within 24 hours of any use.
- A two-credential policy for privileged users.
- Alerting on privileged sign ins and failures.

## SR-07: signed ballot definitions

Voters get their ballot papers only from a **ballot definition**: one signed, versioned document per election. It must be approved by two distinct delegates and activated before polls open.

**What is signed.** Each version stores a payload: canonical JSON (sorted keys, compact separators, UTF-8) holding:
- the election id and the version number;
- `valid_from` and `valid_until`;
- every division, each with its candidates in ballot order (id, given name, surname, party, position);
- `prev_hash`: the SHA-256 of the previous version's payload, or `null` for version 1.

Delegates sign the tag `evoting-ballot-definition-v1` and a newline, followed by the payload, with Ed25519. The stored payload text itself is what gets checked, never a re-serialised copy. Stored versions are never changed or deleted; a change is always a new version.

**Approval.** The keyring (`DELEGATE_KEYRING_PATH`) maps each `key_id` to a delegate and a public key; the app reads only that. A definition needs valid signatures from `REQUIRED_DELEGATE_APPROVALS` (2) **distinct delegates**:
- a signature from an unknown key, or one that does not verify, does not count;
- one delegate counts once, however many keys or copies they sign with.

A definition is also refused outside `valid_from`..`valid_until`, both ends included.

**Activation** (script only; no API endpoint) happens in one transaction. It succeeds only if:
1. the definition verifies;
2. it is exactly the active version + 1, and its `prev_hash` matches the active version;
3. it is at least `MIN_ACTIVATION_LEAD_HOURS` (24) before polls open;
4. polls are not open yet.

Anything else changes nothing and exits with the reason. Polls open and close at `elections.starts_at` and `ends_at`.

**Serving.**
- **Ballot request:** `GET /api/ballot` verifies the active definition on every request and builds the ballot only from its entry for the voter's division, in the same response shape as before. A candidate added to the candidates table later never appears.
- **Submission:** `POST /api/ballot/submit` accepts only rankings of that entry's candidates.
- **Failure:** with no active definition, or one that fails verification, nothing is served: `503 {"detail": "ballot_unavailable"}`, audited as `BALLOT_DEFINITION_INVALID`.
- **Start-up:** the API refuses to start if an election whose polls have not closed has an invalid active definition, or is open with none.

**The delegate script**, inside `backend/` with the virtual environment active:

```
python -m scripts.ballot_definition build --valid-from 2026-11-01T00:00:00+11:00 --valid-until 2027-11-01T00:00:00+11:00 --out definition.json
python -m scripts.ballot_definition sign --definition definition.json --delegate delegate_a
python -m scripts.ballot_definition activate --definition definition.json --signature definition.json.delegate_a.sig.json --signature definition.json.delegate_b.sig.json
```

`build` writes the next version from the current candidates (`--election ID` to choose an election; the latest by default). `sign` writes `{key_id, signature}`. `activate` prints `Activated version N` or `Rejected: <reason>` and exits 1.

**To demonstrate the rejections** with the seeded election, whose polls are already open:
1. `build` the next version, sign it with `delegate_a` only, and `activate` it with that one signature: `Rejected: not_enough_delegates`.
2. Sign it with `delegate_b` as well and activate it with both: `Rejected: polls_open`.

Both are audited as `BALLOT_DEFINITION_REJECTED`.

**Seed fixture.** The seed writes version 1 directly, signed by `delegate_a` and `delegate_b`, with `activated_at` set to polls open minus 25 hours. The 24-hour rule applies to the activation script, and the demo election must already be open.

**Development keys only.** The first use of the script, or of the seed, creates `delegate_a`, `delegate_b` and `delegate_c` private keys and `keyring.json` in `backend/keys/delegates/`, which Git ignores. Never use them for a real election. Nothing under `app/` reads a private key, and a test checks this.

Audit events: `BALLOT_DEFINITION_ACTIVATED` and `BALLOT_DEFINITION_REJECTED` (actor `script`), and `BALLOT_DEFINITION_INVALID` (actor `account:<id>`, or `unknown` at start-up). Each has a reason code only, never payload or signature material.

Run the SR-07 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr07_ballot_definition.py -v
```

Design only, not implemented:
- A delegate key ceremony.
- Delegate keys held on hardware.
- A signing screen.
- Publishing each definition's hash.
- Database-level protection of stored definitions (the database roles SR).

## SR-08: House preference rules

Before a ballot is accepted, the server checks the ranking against the House of Representatives rules (`app/ballot_rules.py`). The candidate list comes from the same verified ballot definition the ballot was served from (SR-07). A ballot arrives as an ordered list of candidate ids: the first id is number 1, the next number 2, and so on. Repeated numbers, gaps and a missing first preference therefore cannot occur, and the interface cannot produce ticks, crosses or writing.

The rules, in order, for a division with N candidates:

1. **Invalid:** a candidate who is not in this division, a candidate listed twice, or more than N entries.
2. **Informal, `blank`:** nothing ranked.
3. **Formal:** all N candidates, each once. The list order is the preference order, and it is stored as submitted.
4. **Informal, `incomplete_order`:** anything else, that is, fewer than N.

| Result | Response |
|---|---|
| Informal | `422 {"detail": "informal_ballot", "reason": "blank"}` or `"reason": "incomplete_order"`. Shown as "Your preferences are incomplete: number every box from 1 to N" |
| Invalid | `422 {"detail": "invalid_ballot"}`, never saying which candidate or rule. Shown as "Your ballot could not be accepted. Please check your preferences" |

**When the rules run.** The check runs inside the SR-03 accept transaction, after the replay check and before the token is used. A used token still gets its receipt (SR-14: recomputed from the token) without any check. A refused ballot changes nothing: the token stays unused, the elector stays `issued` and no ballot is stored, so the voter can correct it and submit again with the same token. The server never takes the client's word that a ballot is formal.

**Audit.** An invalid request is audited as `BALLOT_REJECTED_INVALID` (account only), as possible tampering. An informal ballot is deliberately not audited, because the entry would record what that elector was trying to vote.

**The interface** already requires every candidate to be ranked:
- **Ballot screen:** shows how many boxes are left, highlights the empty ones and will not move on to review until every box is numbered.
- **Review screen:** offers no submit button for an incomplete ballot.

So no ballot made through the interface is informal or invalid. The two messages above appear only if the server disagrees.

**Design assumptions:**
1. The platform does not accept informal ballots. There is no `confirm_informal` flag and informal ballots are never stored. The request to `POST /api/ballot/submit` is unchanged: the ballot token and an ordered list of candidate ids.
2. Every box must be numbered. The one-blank-box savings provision is not implemented, so a list of N-1 candidates is informal and refused. This is stricter than the real House rules. Because the interface already requires every candidate to be ranked, no ballot produced through it is affected.

Run the SR-08 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr08_house_rules.py -v
```

Design only, not implemented:
- **The one-blank-box savings provision.** Under the House rules, a ballot with every box but one numbered consecutively is formal, and the blank box counts as the last preference.
- **Accepting an informal ballot.** This would come with a warning and one explicit confirmation, store the ballot as informal and count it in the informal total. Real informal ballots are votes: they are handed in and counted as informal.

## SR-09: client-side data handling

The elector's selections exist only in the browser tab's memory, and only while a ballot is open. When the session ends, nothing about the ballot is left in the browser.

**Review before every submission.** This was already in place, so SR-09 did not change it:
- **Submit only from Review.** Ballots are submitted only from the Review screen. It lists every candidate with their preference number and has no submit button for an incomplete ballot. **Submit ballot** works only after the voter ticks "I have checked my numbers".
- **Change keeps the numbers.** **Change ballot** goes back to the ballot paper with the numbers kept.
- **The receipt shows no selections.** It shows the receipt code, the time accepted, the election and the division.

**Memory only.**
- **React state only.** The ballot paper, its one-time ballot token and the ranking are React state in `App.tsx`.
- **No browser storage.** Nothing about the ballot is written to `localStorage`, `sessionStorage`, IndexedDB, cookies, the URL or the history state. The app never adds a history entry.
- **No form values kept.** The ballot paper has no form fields, and the confirm box has `autocomplete="off"`, so the browser keeps no form values.
- **Enforced by a test.** The project has no ESLint, so a test enforces the rule. `src/lib/noBrowserStorage.test.ts` scans every source file under `frontend/src`, except tests. It fails `npm test`, and so CI, if any file uses `localStorage`, `sessionStorage`, `indexedDB` or `document.cookie`.

**Where the ballot is cleared.** `clearBallotState` in `src/lib/clientSession.ts` is the only code that clears it:

| When | How |
|---|---|
| The ballot is accepted | `acceptBallot` clears it before the receipt shows |
| Sign out: top bar, the session warning, the receipt screen's Done and its 60-second timer | SR-15: the terminal reset: cleared first, then `POST /api/auth/logout`, then the start page is loaded afresh. A failed logout still leaves it cleared |
| The session timer runs out | SR-15: the terminal reset |
| No input for 120 seconds (SR-15) | The terminal reset |
| The session is lost: a 401 when submitting, extending the session or loading the ballot | SR-15: the terminal reset |
| Any other failure to extend the session or load the ballot, or `already_voted` on submit | `returnToSignIn`, then `endSession`: cleared first, then `POST /api/auth/logout`, and the reason is shown on the sign-in screen |
| The page is left (`pagehide`) | Cleared at once |

Ballot and Review render only while a ballot is open, so their own state goes with it: the undo history, the screen reader announcements, the confirm tick and messages. Closing the tab discards all of it anyway.

**Back/forward cache.** A browser can keep a whole page, memory included, and show it again on Back or Forward. `registerPageLifecycle` clears the ballot on `pagehide`. When `pageshow` reports a page restored from that cache (`event.persisted`), it reloads the page, so the app starts again at sign in. `App.tsx` removes both listeners when it unmounts.

**No caching.**
- **The API.** One middleware in `app/main.py` adds `Cache-Control: no-store` and `Pragma: no-cache` to every API response. That includes errors from routes, dependencies and FastAPI's own handlers (401, 404, 422, 429, 503) and redirects.
- **The dev and preview servers.** `npm run dev` and `npm run preview` send `Cache-Control: no-store` for the app's pages and files (`vite.config.ts`).

**Inspection.** After a sign-out, a timeout and a submission, the team inspects the browser by hand in Chrome DevTools, following [docs/SR-09_INSPECTION.md](docs/SR-09_INSPECTION.md). Screenshots go in `docs/sr09-evidence/`.

Run the SR-09 tests. The backend tests run inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr09_cache_headers.py -v
```

The frontend tests run inside `frontend/`:

```
npx vitest run src/lib/clientSession.test.ts src/lib/noBrowserStorage.test.ts
```

Limits:
- **Unhandled errors.** A response for an unhandled server error (500) comes from Starlette's outermost error handler, outside the middleware, so it does not get the two headers. It contains only `Internal Server Error`.
- **The server session after closing a tab.** Leaving or closing the tab clears the ballot but does not end the server session. That session still ends at its fixed time (SR-04), and the next page load starts at sign in.
- **Production hosting.** The `no-store` header for the app's own files is set only by the Vite dev and preview servers. A production web server would need the same setting.

Design only, not implemented:
- **A `Clear-Site-Data` header on sign out.** This would tell the browser to drop the site's storage, cache and cookies.
- **An automated browser-based inspection test.** This would drive a real browser through sign-out, timeout and submission, then check storage, the page and the Back button. The checks are done by hand for now (above).

## SR-10: TLS 1.3 for ballot transmission

Every request between the browser and the server travels over TLS 1.3, including the ballot itself, the sign-in and the staff page.

**Approved protocols: TLS 1.3 only.** The system security specification approves no other protocol for this prototype. TLS 1.2 and older are refused.

**One TLS entry point.** `python -m app.serve` (`app/serve.py`) serves the API and the built frontend (`frontend/dist`, including `staff.html`) at https://localhost:8443. There is no plaintext listener and no fallback.
- **TLS 1.3 only.** uvicorn has no setting for the minimum TLS version, so `serve.py` loads the uvicorn configuration and then sets the minimum on the SSL context uvicorn built. A TLS 1.2 client fails the handshake.
- **This computer only, no forwarded headers.** It listens on 127.0.0.1 only. It ignores `X-Forwarded-*` headers, which uvicorn would otherwise trust from 127.0.0.1, so no client can claim another scheme or address. SR-01's per-IP limit keeps using the real connection.
- **No certificate, no server.** It refuses to start (exit code 1) if the certificate or the key is missing, and says how to create them.
- **Plaintext gets no HTTP response.** A plain HTTP request sent to port 8443 is ended by the TLS layer itself.
- **The frontend never shadows the API.** The built frontend is the router's fallback: it answers only when no API route matched, so it can never hide an API path. Without `frontend/dist` (tests, CI) the API runs on its own.

**Plaintext refused inside the app.**
- **`tls_required`.** The `require_tls` middleware in `app/main.py` is the outermost middleware. A request that did not arrive over HTTPS gets `400 {"detail": "tls_required"}` before any other middleware or route runs. That covers a plain `uvicorn app.main:app`.
- **HSTS on every HTTPS response.** Errors and redirects included, each HTTPS response carries `Strict-Transport-Security: max-age=<HSTS_MAX_AGE>`, next to SR-09's `Cache-Control: no-store`.

**Strict certificate validation.**
- **One development certificate.** `python -m scripts.dev_certs` creates one self-signed certificate in `certs/`. It covers `localhost` and `127.0.0.1`, uses ECDSA P-256 with SHA-256, and is valid for 365 days. It is a server certificate, not a CA, so trusting it vouches for nothing else.
- **The key.** It is readable by its owner only where the operating system supports that (not on Windows). Existing files are kept unless `--force` is given.
- **Validation is never turned off.** Browsers, curl and the Vite proxy check the certificate as usual once it is trusted. No setting, flag or environment variable anywhere in the project disables the check.

**HSTS on localhost.**
- **Why it is short locally.** HSTS is remembered per host name and ignores the port. A long value would make the browser insist on HTTPS for every `localhost` port, including the Vite dev server on 5173.
- **The two values.** `.env.example` sets `HSTS_MAX_AGE=300` (5 minutes). The code default is one year (`31536000`), for a real deployment.
- **To clear it in Chrome:** open `chrome://net-internals/#hsts`, enter `localhost` under "Delete domain security policies" and select Delete.

To verify all of this by hand (the browser's Security panel and six curl checks), see [docs/MANUAL.md](docs/MANUAL.md), section 6.

Run the SR-10 tests, inside `backend/` with PostgreSQL running. The handshakes run in memory, so no port is opened:

```
pytest tests/test_sr10_tls.py -v
```

Limits:
- **The registration cookie** is still not marked `Secure` (unchanged since registration was added), although it now travels only over TLS.
- **Unhandled server errors.** A 500 response comes from Starlette's outermost error handler, outside the middleware, so it carries neither HSTS nor `no-store` (as in SR-09).
- **`backend/Dockerfile`** still starts a plain `uvicorn` on port 8000, so that image would answer every request with `tls_required`. Nothing uses it yet (not Docker Compose, not CI), and SR-10 does not change Docker.

**SR-10 design only, not implemented:**
- **Internal connections.** TLS for the database connection and for internal services.
- **Certificate lifecycle.** Certificate rotation, and certificates issued by a real certificate authority instead of a self-signed one.
- **OCSP stapling.**
- **Certificate pinning in a native voting client.**
- **The plain-HTTP Vite dev server.** Today it is kept to development by instruction only. A deployment would not run it at all; only the TLS entry point would be reachable.

## SR-11: ballots encrypted at rest

Every stored ballot is encrypted with AES-256-GCM. Before each release, a storage audit must find no plaintext ballot record.

**What is encrypted.** The whole ballot is one payload, serialised as canonical JSON (sorted keys, no spaces, UTF-8): `{"division_id": ..., "ranked_candidate_ids": [...]}`.
- **Encrypted with:** `app/ballot_crypto.py`, using AES-256-GCM from the `cryptography` package and a 32-byte key.
- **What stays readable:** a `ballots` row keeps only the random ballot id and the election id. The division used to be a readable column and is now inside the ciphertext.
- **Nothing else held ballot content.** Receipts (`ballot_tokens`), participation (`voter_participation`), the audit log and the application logs held none, and still hold none.

**Stored format** (`ballots.encrypted_payload`, BYTEA): 1 version byte (`0x01`), a 12-byte nonce, then the ciphertext with its 16-byte GCM tag.
- **A fresh nonce every time.** Each ballot gets a new random nonce from `os.urandom`, so two identical ballots never look alike.
- **Bound to its own row.** The associated data is `"{ballot_id}|{election_id}"`, so the application chooses the ballot id before the INSERT. A ciphertext copied to another row or election does not decrypt.
- **One error for every failure.** A wrong key, altered bytes, an unknown version or a short value all raise `BallotDecryptionError`, with a message that contains none of the ballot.
- **The version byte is the hook for later key rotation.**

**The key.** `python -m scripts.gen_ballot_key` writes 32 random bytes to `BALLOT_KEY_FILE` (default `backend/keys/ballot.key`, which is gitignored).
- **Created safely.** The file is created owner-only (0600), and the script never overwrites an existing key without `--force`.
- **No key, no API.** The API refuses to start if the key is missing or is not exactly 32 bytes. On POSIX systems it also refuses if the group or others have any access; that check is skipped on Windows, which has no such permission bits.
- **No way around it.** There is no default key, no plaintext mode and no setting that turns encryption off.
- **Never logged.** Nothing logs or prints the key, a plaintext ballot or a ciphertext.

**Counting.** The prototype has no counting or results feature, so none was added. `decrypt_ballot` opens a ballot in memory only. A future count must use it the same way, and never write decrypted ballots to disk, logs or the database.

**Error responses.** FastAPI's default 422 answer repeats the submitted input. For a malformed `POST /api/ballot/submit`, the answer now keeps only where and why validation failed, so it can never repeat the ranking. Other routes are unchanged.

**Migration `0009`.** It removes the readable columns and adds `encrypted_payload`. Assumption: the prototype database contains only seed and test data; old plaintext test ballots are discarded and must be recreated by re-running the seed script and casting new test ballots.
- **What else is removed:** the used tokens (which hold those ballots' receipts) and the `voted` participation rows.
- **What is kept:** electors, the roll, elections, ballot definitions, staff, the audit log, unused tokens and `issued` rows.
- **Downgrade:** it works only while no ballots are stored. Otherwise it stops and explains that SR-11 encryption cannot be reversed without the key, and that the plaintext data was discarded.

**Pre-release audit.** Run `python -m scripts.audit_ballots` inside `backend/` against the release database. It prints PASS, FAIL or SKIPPED for each check, then a summary, and exits with code 1 if any check fails:
- **a. Ballot records.** Every row starts with `0x01`, is at least 29 bytes, and decrypts with its own ballot and election id. Readable JSON or a ballot field name in the bytes fails.
- **b. Ballots columns.** The table has only `id`, `election_id` and `encrypted_payload` (bytea), so none of the old plaintext columns.
- **c. Other tables.** `ballot_tokens`, `voter_participation` and `audit_log` have only their reviewed columns.
- **d. The key.** The key file exists and is exactly 32 bytes, and git ignores it and does not track it. Without git, or outside a git repository, the git part shows as **SKIPPED with a warning**, never as PASS.
- **e. Logs.** Neither the audit log nor any `*.log` file in the project contains `division_id` or `ranked_candidate_ids`.

It prints only ballot ids and reasons, never a ballot. The release steps are in [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md), and the manual checks are in [docs/MANUAL.md](docs/MANUAL.md), section 7.

Run the SR-11 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr11_encryption.py -v
```

The tests use their own temporary key (`tests/conftest.py`), so neither the tests nor CI need a `keys/` folder.

**Limit.** In the prototype the key is on the same machine as the database. This protects against a stolen database dump or backup. It does not protect against a fully compromised application server, which can read both.

**SR-11 design only, not implemented:**
- **Better key storage.** Keep the key in a KMS or HSM, with envelope encryption and a data key per election.
- **Key rotation and re-encryption.** The version byte is the hook for this.
- **Encryption below the application.** Disk or volume encryption, and encrypted backups.
- **PostgreSQL transparent data encryption (TDE).**
- **An automatic audit job in the release pipeline.** For now a person runs the audit, as part of the release checklist.

## SR-12: identity and ballots kept apart

From the moment a ballot is accepted, and for as long as it is kept, no persistent record or identifier can link an elector to their ballot. Before each election, checks of the schema, data, logs, backups and exports confirm it.

**Two stores.** `app/stores.py` puts every table on one side. `tests/test_sr12_separation.py` fails if a new table has no side.

| Side | Tables |
|---|---|
| Identity (`IDENTITY_TABLES`) | `electoral_roll`, `accounts` (electors and staff), `sessions`, `registration_sessions`, `voter_participation` (issued or voted, never how), `audit_log`. Also the public election setup: `elections`, `divisions`, `candidates` and `ballot_definitions`. These hold no ballot content and are referenced by the roll and participation |
| Ballot (`BALLOT_TABLES`) | `ballots` (random id, election id, SR-11 ciphertext), `ballot_tokens` (random id, election id, token hash, used flag and receipt hash since SR-14) and, since SR-13, `ballot_chain` (the hash chain over stored ballots) |

Sign-in rate-limit counts are identity-side too, but they live in memory only. `alembic_version` is Alembic's own bookkeeping and belongs to neither side.

**What changed (migration `0010`).** Existing data is assumed to be test data only, and it is kept.
- **Times on the ballot side.** `ballot_tokens.expires_at` and `consumed_at` matched the `BALLOT_TOKEN_ISSUED` and `BALLOT_ACCEPTED` audit entries, which name the elector, to the second. Both are removed.
- **Token validity.** A token is now unused while its receipt is empty (SR-14: while its `consumed` flag is false). It is usable while its election is open and the elector is signed in (SR-04), so `BALLOT_TOKEN_MINUTES` and `400 ballot_expired` are gone.
- **Exact times stay on the identity side.** The audit log, sessions and participation keep theirs.
- **Foreign keys.** `ballots` and `ballot_tokens` no longer have foreign keys to `elections`: the election id is a plain value. So the ballot side has no foreign key at all.
- **Database errors.** They no longer show their SQL parameters (`hide_parameters=True`). If storing an accepted ballot fails, the error raised carries none of the database's text about the row, so the server log cannot repeat a ballot id, token hash or receipt.
- **Bulk reads.** Every bulk read of ballots (`stores.ballot_rows`: the export, the SR-11 audit, any future count) is ordered by the random ballot id, never by arrival order or time.
- **Audit events.** `BALLOT_TOKEN_ISSUED` and `BALLOT_ACCEPTED` hold only the event type and the elector's account. The access log has request lines only, and no exception handler includes a ballot value.

**Export the ballot side.** Inside `backend/`:

```
python -m scripts.export_ballots --out exports/ballots.jsonl
```

This writes one line per ballot, `{"ballot_id", "election_id", "encrypted_payload_b64"}`, ordered by ballot id. It reads the `ballots` table only and never decrypts. `exports/` is in `.gitignore`.

**Backups: always two separate dump files.** Never back up the whole database as one file. Run these from the repository folder (PowerShell). Change `-U` and `-d` if your settings differ:

```powershell
New-Item -ItemType Directory -Force ..\evoting-backups | Out-Null
docker compose exec db pg_dump -U evoting -d evoting --no-owner -f /tmp/identity.sql -t public.accounts -t public.audit_log -t public.ballot_definitions -t public.candidates -t public.divisions -t public.elections -t public.electoral_roll -t public.registration_sessions -t public.sessions -t public.voter_participation -t public.alembic_version
docker compose exec db pg_dump -U evoting -d evoting --no-owner -f /tmp/ballots.sql -t public.ballots -t public.ballot_tokens -t public.ballot_chain
docker compose cp db:/tmp/identity.sql ..\evoting-backups\identity.sql
docker compose cp db:/tmp/ballots.sql ..\evoting-backups\ballots.sql
docker compose exec db rm /tmp/identity.sql /tmp/ballots.sql
```

- **What each file holds.** The identity dump holds `IDENTITY_TABLES` (plus `alembic_version`, so a restore knows its revision). The ballot dump holds `BALLOT_TABLES` only.
- **Encrypt them separately.** Use a different key for each, for example `gpg --symmetric --cipher-algo AES256`. Store them in different places, never in the repository, and never together with the SR-11 ballot key.

**Separation audit.** Inside `backend/`, before each election:

```
python -m scripts.audit_separation --file ..\..\evoting-backups\identity.sql --file ..\..\evoting-backups\ballots.sql --file exports\ballots.jsonl
```

It prints PASS, FAIL or SKIPPED per check, then `SR-12 separation audit: PASS` or `FAIL (n checks)`, and exits with code 1 if any check fails:
- **a. Foreign keys.** Every table has a side, and no foreign key joins the sides.
- **b. Ballot-side columns.** No ballot-side column name contains `elector`, `roll`, `user`, `session` or `agent`, or has the word `ip`. No ballot-side column has a timestamp or time type, and none is serial or identity.
- **c. Identity-side data.** Every ballot id, token id, token hash and receipt hash is checked against every identity-side row and the audit log. The text is scanned with patterns for 64-hex hashes, UUIDs and 32-hex receipt references, and each match is looked up in a set. SR-14: a 32-hex value is hashed first, so a leaked reference matches its stored hash.
- **d. Logs.** The same scan runs on the audit log, every file in `LOG_DIR` (default `logs/`), and every `*.log` file in the project.
- **e. Files given with `--file`.**
  - In a plain SQL dump, ballot identifiers may appear only inside the ballot tables' own `COPY` blocks or `INSERT` lines.
  - Any other file (an export) fails if it holds a ballot identifier together with an identity marker: an e-mail address, an elector's or staff member's username, or an account or roll id.
  - Without `--file`, this check is SKIPPED.

It prints only counts and table or file names.

Run the SR-12 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr12_separation.py -v
```

**Residual risks, and SR-12 design only (not implemented):**
- **Timing correlation from outside the system.** An observer who watches live network traffic or the web server's access log can match an elector's sign-in to the moment a ballot is stored. The defence is a shuffled batch queue with a minimum batch size, so ballots are written in groups in random order. It is not implemented: it needs a background worker and a flush rule at election close, and it would conflict with immediate receipts in a small demo.
- **Separate databases or schemas with separate database roles.** For now both sides share one database and one role; only the application keeps them apart.
- **Scheduled destruction at the end of the retention period.** The retention period itself is an assumption taken from the electoral rules. The prototype deletes nothing automatically.
- **Physical row order.** PostgreSQL stores rows in pages roughly in insertion order, so someone with raw disk access may still see part of the arrival order. Counting and export never rely on it: they order by the random ballot id.
- **Encrypted separate backups.** The two dump files and how to encrypt them are documented above. No tool makes or encrypts them automatically.

## SR-13: integrity-protected ballot storage

Every accepted ballot ends up in an integrity-protected repository: a SHA-256 hash chain per election, with signed checkpoints. The integrity tests and the verify command detect insertion, deletion, modification and reordering of recorded ballots. **The chain detects tampering; it does not prevent it.**

**The chain** (`ballot_chain`, `app/ballot_chain.py`). One entry per sealed ballot: election id, position, batch number, ballot id, previous hash and entry hash.
- **What the entry hash covers.** SHA-256 over a version tag, the previous entry's hash, the ballot id, the election id, and the SHA-256 of the stored SR-11 ciphertext. Changing a ballot's bytes, removing or adding one, or swapping two breaks the chain.
- **Where it starts.** Position 1 links to a start value derived from the election id.
- **Nothing to decrypt.** Verifying reads only the ciphertext, so it never decrypts a ballot and never needs the SR-11 key.
- **Unchanged parts.** The `ballots` table and the SR-03 accept transaction are unchanged. The chain holds no time, elector, roll, session or IP.

**Sealing in shuffled batches.** Ballots are not chained when they are accepted. The returning officer seals them, inside `backend/`:

```
python -m scripts.seal_ballots --election <election id>           # needs at least MIN_SEAL_BATCH (10) unsealed ballots
python -m scripts.seal_ballots --election <election id> --final   # after polls close: the last batch, any size
```

- **One transaction, one seal at a time.** Each seal runs in one transaction under a per-election lock, so two seals cannot interleave. It refuses an empty batch, a batch below `MIN_SEAL_BATCH` (unless `--final`), anything after a final seal, and a chain that already fails verification.
- **Order within a batch.** Ballots are ordered by their random ballot id, never by arrival, so a position reveals nothing about when a ballot came in (SR-12).
- **After the commit.**
  - It appends one signed checkpoint line to `CHECKPOINT_DIR/<election id>.jsonl` (default `backend/checkpoints/`, never committed). The line holds the election, batch number, entry count, head hash and final flag, signed with Ed25519.
  - It verifies the whole chain and prints the head hash.
  - It audits `BALLOT_BATCH_SEALED` with the batch number and count only.
- **After a `--final` seal,** no more ballots may be accepted for that election. One that arrives later fails verification (`unsealed_after_final`).

**Keys.** Create them once, inside `backend/`:

```
python -m scripts.gen_checkpoint_key
```

- **Where they go.** This writes `keys/checkpoint_private.pem` (0600 where supported) and `keys/checkpoint_public.pem`. It never overwrites without `--force`.
- **Who uses which key.** Only the seal script uses the private key. The server side reads only the public key, and only when verifying. The API starts without either, so CI and tests need no keys.

**Verifying.** Inside `backend/`:

```
python -m scripts.verify_chain --election <election id>
```

It prints one PASS or FAIL line per check group, the entry count and the head hash, and exits with code 1 on any failure. The reason codes are:
- `bad_entry_hash`, `broken_link`: a wrong entry hash or a broken link, including a ballot whose bytes changed;
- `gap_or_reorder`: positions not continuous from 1, or batches out of order;
- `missing_ballot`: a chain entry whose ballot is gone;
- `missing_checkpoint`, `malformed_checkpoint`, `bad_checkpoint_signature`: a checkpoint file or line that is missing, unreadable or wrongly signed;
- `checkpoint_mismatch`: a checkpoint that does not match the chain at its batch;
- `tail_mismatch`: a last checkpoint that does not match the chain's tail, which catches a truncated tail;
- `unsealed_after_final`: a ballot that is not in the chain after a final seal.

Failures are audited as `BALLOT_CHAIN_VERIFY_FAILED` with the reason codes only. No option skips a check. There is no counting feature; any future count must call `verify_chain` first and refuse to count on failure.

**Append-only tables.** Database triggers refuse every UPDATE and DELETE on `ballots` and `ballot_chain`, with no bypass flag; INSERT is allowed. The triggers do not stop `TRUNCATE`, which the development `python -m scripts.seed --reset` relies on. They do not stop a database owner either, who can disable them. That is why the chain and the checkpoints exist.

**SR-12 consistency.** `ballot_chain` is a ballot-side table, and its entry hashes count as ballot identifiers in the separation audit. That audit now also refuses order-number columns (position, seq, batch...) on the ballot side, with one narrow exception: `ballot_chain.position` and `batch_no`, which follow the random ballot-id order. The ballot backup dump includes `ballot_chain`.

Run the SR-13 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr13_chain.py -v
```

**SR-13 assumptions:**
- **Order is fixed, but only coarsely.** The chain fixes ballot order, so the order is random within a batch, and batches reveal only coarse timing. This protects SR-12.
- **Key and checkpoints on one machine.** In the prototype the signing key and the checkpoint folder sit on the same machine as the database. Someone who controls all three can rebuild a consistent chain. Recording the head hash with each release limits this.
- **Triggers can be bypassed by a database owner.**

**SR-13 design only, not implemented:**
- a background sealing worker;
- signing keys in an HSM, or split between two delegates;
- write-once or off-host checkpoint storage;
- external anchoring of the head hash;
- a Merkle tree;
- least-privilege database roles.

## SR-14: ballot acceptance confirmation

Once a ballot is durably accepted, the voter gets a confirmation within 10 seconds. It holds only a 128-bit reference and no ballot content.

**The response.** `POST /api/ballot/submit` still answers `200 {"receipt_id": "..."}`, with no other field.
- **New format.** `receipt_id` used to be an 8-character random code (`ABCD-EFGH`). It is now 32 lowercase hex characters (128 bits).
- **No content.** It holds no candidate, ranking, division, ballot id, token or hash.
- **Headers unchanged.** The response still has `Cache-Control: no-store` (SR-09) and HSTS (SR-10).

**The reference.** It is the first 16 bytes of SHA-256 over `evoting-receipt-v1|` followed by the ballot token, written as hex.
- **Derived, never stored.** The server stores only `receipt_hash`, the SHA-256 of the reference, on the used token row. The reference itself is stored nowhere and logged nowhere. There is no separate random reference.
- **The same on retry.** A retry with the same token recomputes the reference and checks its hash against the stored one (constant-time compare). Then it returns the same reference and stores no second ballot.
- **Generic error otherwise.** A used token whose stored hash does not match gets the generic `400 invalid_ballot`, and so does a token used before SR-14 (no stored hash).
- **Shown once.** The token lives only in the page's memory (SR-09) and is cleared when the ballot is accepted. So a lost reference cannot be recovered: neither the voter nor the server can recompute it.
- **Not on the identity side.** Neither the reference nor its hash is in `voter_participation`, `sessions`, the audit log or any log line. `ballots`, `ballot_chain`, SR-11 encryption and the SR-13 chain are unchanged.

**Only after the commit.** The SR-03 transaction order is unchanged. The reference is worked out before the token is consumed, but it is returned only after the commit. If anything fails before the commit, everything rolls back and the voter gets an error with no reference.

**Within 10 seconds.** `ACCEPT_TIMEOUT_SECONDS` (default `8`, allowed `1` to `9`) sets PostgreSQL's `lock_timeout` and `statement_timeout` for the accept transaction only (`SET LOCAL`).
- **On a timeout.** If a lock wait or a statement takes longer, the transaction rolls back and the voter gets `503 {"detail": "try_again"}`.
- **Nothing stored.** The token stays unused, the elector stays `issued` and no ballot is stored, so the same token works on retry.
- **In the browser.** The frontend shows its usual "Your ballot could not be submitted. Try again, or ask a polling official for help." and keeps the token.
- **No server retries.** There is no retry loop and no background worker.

**Migration `0012`.**
- **Columns.** Replaces `ballot_tokens.receipt_reference` with `consumed` (the used flag) and `receipt_hash`.
- **Tokens used before SR-14.** They stay `consumed`, but have no hash. A replay of one gets the generic error, because its reference cannot be worked out again.
- **Untouched.** Ballots and chain rows.
- **Downgrade.** Puts `receipt_reference` back, with the placeholder `XXXX-XXXX` on used tokens.

After pulling, run `alembic upgrade head`, then `python -m scripts.seed --reset` or cast new test ballots.

**SR-12 audit.** Every receipt hash counts as a ballot identifier, and a leaked reference fails the audit too (check c above). The SR-11 storage audit also knows the new token columns.

Run the SR-14 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr14_confirmation.py -v
```

**SR-14 assumptions:**
- **A separate used flag.** `consumed` keeps tokens used before SR-14 counted as used, now that the reference column is gone.
- **Hex.** The 128 bits are written as 32 lowercase hex characters.
- **Each wait is bounded, not the total.** The time limit applies to each lock wait and each statement. An accept is a handful of short statements, so in practice it ends well inside 10 seconds. This has not been load tested.
- **No status field.** The `200` status itself says the ballot was accepted. As before, the body holds only the reference.
- **Old test tokens.** The prototype database holds only seed and test data, so tokens used before SR-14 need no reference.

**Known display issue.** The receipt screen shows the reference in its large code style, which was sized for the old 9-character code. The 32 characters do not wrap, so they run past the card. SR-14 does not change the frontend.

**SR-14 design only, not implemented:**
- a public lookup, where a voter checks a reference;
- individual verifiability (a voter checking that their ballot was counted as cast);
- signed receipts;
- load testing;
- latency monitoring.

## SR-15: ending finished and abandoned sessions

On every voting device, polling-place terminals included, the app ends the elector's session, clears all ballot data and returns to the start screen within 5 seconds of the elector finishing or abandoning the session.

**When it happens.**

| Trigger | When |
|---|---|
| Done | The elector selects **Done** on the receipt screen |
| Receipt countdown | 60 seconds after the receipt appears (`VITE_RECEIPT_SECONDS`). The screen shows "This screen will clear in N seconds." |
| Idle | 90 seconds without input (`VITE_IDLE_SECONDS`) opens "Are you still there?". 30 more seconds without input (`VITE_IDLE_WARNING_SECONDS`) ends the session: 120 seconds in all |
| Sign out | **Sign out** in the top bar or in the SR-04 session warning |
| Session expiry | The SR-04 session timer runs out |
| Lost session | A 401 from a signed-in call: loading the ballot, submitting it or extending the session |

**The idle timer** runs on every elector screen: sign in, code entry, registration, ballot and review. The receipt screen has its own countdown instead.
- **What counts as input.** `keydown`, `pointerdown`, `pointermove`, `wheel` and `touchstart` on the window, with at most one timer restart a second.
- **The warning.** It is an alert dialog with one button, **I'm still here**, which gets the focus. Any input, or the button, closes the warning and restarts the 90 seconds.
- **Never two warnings.** If the SR-04 session warning would show at the same time, the one that ends sooner is shown.
- **A fresh start page.** There, the timer starts at the first input. A blank start page holds nothing to clear, and every session begins with input on it.

**The receipt screen** shows the SR-14 reference, a **Done** button and the countdown. Focus moves to its heading when it opens. Screen readers hear the countdown at 30, 10 and 5 seconds, not every second.

**The reset** (`frontend/src/lib/terminalReset.ts`). Every trigger above calls the same function. It does three things, in order:
1. clears the ballot, its token, the selections, the receipt and the rest of the app's state, through the SR-09 `clearBallotState`;
2. calls `POST /api/auth/logout`, aborted after 3 seconds (`VITE_RESET_LOGOUT_TIMEOUT_MS`), and ignores any error;
3. loads the start page afresh with `window.location.replace`. This discards everything in memory, and Back cannot return to the old session.

More about the reset:
- **5 seconds, even with the server down.** A safety timer loads the start page 4.5 seconds after the reset starts, even if the logout and its abort both stall.
- **Once only.** Only the first call runs. Pressing Done just as the countdown ends resets once.
- **The reason** (`done`, `receipt_timeout`, `idle_timeout`, `sign_out`, `session_expired` or `unauthorised`) exists only for readable code and tests. It is never logged, stored or sent.
- **No message after a reset.** The start page is loaded afresh, and nothing may be kept in browser storage (SR-09). So it no longer says "You have signed out" or "Your session ended".
- **Messages that are still shown.** "You have already voted" and "You are not enrolled" still appear. Those cases return to sign-in without a reset, and no ballot is open by then.
- **On page close.** The SR-09 `pagehide` clearing is unchanged.

**Everywhere, and always on.** The same rules apply on polling-place terminals and on personal devices. There is no terminal mode and no setting that turns the reset off. The staff page (SR-06) keeps its own session rules.

**The server.** Logout already did what SR-15 needs, so no backend logic changed.
- **Ends the session.** It deletes the session row and clears the cookie with the same attributes it was set with: Secure, HttpOnly, SameSite=Strict and path `/`.
- **Same answer every time.** It answers `204` with no session, an unknown one or an expired one, so a repeated reset never shows an error.
- **No audit entry,** so resets cannot flood the audit log.
- **Unchanged.** Session lifetimes and the SR-04 60-second rule after a ballot.

**Shorter timers for a demo.** Set these in `frontend/.env` (copied from `frontend/.env.example`):

| Variable | Default | Allowed |
|---|---|---|
| `VITE_IDLE_SECONDS` | `90` | 5 to 600 |
| `VITE_IDLE_WARNING_SECONDS` | `30` | 5 to 120 |
| `VITE_RECEIPT_SECONDS` | `60` | 5 to 120 |
| `VITE_RESET_LOGOUT_TIMEOUT_MS` | `3000` | 500 to 3000 |

- **Demo only.** Lower values exist only so a demo can be recorded quickly, for example `VITE_IDLE_SECONDS=10` and `VITE_IDLE_WARNING_SECONDS=5`.
- **No way to turn it off.** A missing, non-numeric, zero or negative value uses the default, and any other value is clamped to its range.
- **Before a release,** remove the demo values and build again.

**Build again after frontend changes.** The backend serves the built frontend over HTTPS (SR-10), and these settings are built into it. So after pulling this change, or changing a setting, run `npm run build` in `frontend/`, then restart `python -m app.serve`.

**A polling-place style demo (optional).** Start Chrome in kiosk mode with a fresh, throwaway profile (PowerShell), and close it with Alt+F4:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --kiosk --incognito --user-data-dir="$env:TEMP\evoting-kiosk" https://localhost:8443
```

This only shows what a terminal session looks like. Real terminal lockdown is design only (below).

Run the SR-15 tests:

```
cd frontend
npm test                                   # includes src/lib/terminalReset, idleController, receiptCountdown and terminalSettings tests
cd ../backend
pytest tests/test_sr15_logout.py -v
```

**SR-15 assumptions:**
- **One app everywhere.** Supervised polling-place terminals and electors' own devices use the same web app. Personal devices may be shared too, so the reset applies everywhere.
- **The browser does the timing.** If the browser is closed, crashes or is tampered with, the server session still ends at its SR-04 expiry: 10 minutes after sign in, or 60 seconds after a ballot.
- **How the 5 seconds is measured.** In the browser, from the finish or abandonment event to the start screen.
- **60 seconds is enough** to note the SR-14 reference.
- **A fresh start page waits for input** before its idle timer starts (see above).
- **Lost session means signed-in calls only.** A 401 resets only after the ballot, submit or extend calls. The sign-in steps' own 401 for wrong details still shows the usual sign-in message.

**SR-15 design only (polling-place terminals), not implemented:**
- kiosk mode with a fresh browser profile for each session;
- managed, signed terminal images;
- Secure Boot;
- application allow-listing;
- a watchdog that restarts the voting browser;
- a server-side idle timeout with a heartbeat;
- a `Clear-Site-Data` header on logout.

## Folder layout

```
backend/             FastAPI app, Alembic migrations, seed script and tests
frontend/            React app
docs/                MANUAL.md (files and how to run the app), SR-09_INSPECTION.md and sr09-evidence/ (SR-09), RELEASE_CHECKLIST.md (SR-11)
certs/               SR-10: the development TLS certificate and key (python -m scripts.dev_certs). Never committed
exports/, logs/      SR-12: ballot-side exports and server log files. Never committed
backend/checkpoints/ SR-13: signed ballot chain checkpoints, one file per election. Never committed
docker-compose.yml   PostgreSQL 16 for local development
```
