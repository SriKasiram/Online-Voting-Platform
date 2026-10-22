# Electronic Voting Platform Prototype

Prototype for the Electronic Voting Platform group assignment. It covers the House of Representatives voting flow only. Senate voting and overseas voting are design only.

Stack: React with TypeScript (Vite), FastAPI (Python 3.12, SQLAlchemy 2.0, Alembic), PostgreSQL 16.

New to the project? [docs/MANUAL.md](docs/MANUAL.md) lists every file and shows how to start, reset and stop the app.

## Status

| Part | State |
|---|---|
| `frontend/` | Register, two-part sign in, tap-to-rank ballot, review and receipt screens. All data comes from the backend |
| `backend/` | Registration for people on the electoral roll, sign in with a password and an authenticator app, the ballot and submission. Ballot encryption and signing come in later stages |
| `docker-compose.yml` | PostgreSQL 16 for local development |

The frontend gets all its data from the backend, so start the backend first, then the frontend.

```
Browser -> frontend dev server (5173) -> /api proxy -> FastAPI (8000) -> PostgreSQL (5432)
```

## Run the backend

You need Docker (for PostgreSQL) and Python 3.12. Start from the repository root.

### 1. Settings

```
cp backend/.env.example backend/.env           # macOS / Linux
Copy-Item backend\.env.example backend\.env    # Windows PowerShell
```

Open `backend/.env` and set two values:

- `POSTGRES_PASSWORD`: a long random value. Do this before step 2: PostgreSQL stores the password the first time the database starts and ignores later changes to `.env`. If you see `password authentication failed for user "evoting"`, the two have drifted apart (see step 2).
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

### 4. Create the tables

```
alembic upgrade head
```

### 5. Load the seed data

```
python -m scripts.seed
```

This adds one open House of Representatives election, three Victorian divisions (Melbourne, Kooyong and Macnamara) with 4 to 6 candidates each, and one electoral roll entry for a reviewer (see [Registering as a reviewer](#registering-as-a-reviewer)). There are no accounts: everyone registers through the app. Running the script again duplicates nothing and gives the reviewer's enrolment code a fresh one-year expiry.

`python -m scripts.seed --reset` deletes all data, including every vote cast, and loads the seed data again. Use it if your database was created before registration existed: older demo accounts can no longer sign in.

Every seed run ends by signing the electoral roll (SR-02), and the first run creates development keys in `backend/keys/`. The API will not start until the roll is signed. If your database existed before SR-02, run `alembic upgrade head` and then `python -m scripts.sign_roll` (or reseed).

### 6. Run the API

```
uvicorn app.main:app --reload
```

- http://127.0.0.1:8000/api/health returns `{"status": "ok"}`
- http://127.0.0.1:8000/api/divisions lists the divisions stored in the database
- http://127.0.0.1:8000/docs lists every endpoint and lets you try them

### 7. Run the tests

```
pytest
```

PostgreSQL must be running. Every run deletes and rebuilds a separate `evoting_test` database from the migrations. The tests create their own data and never rely on the seed, so your development data is never touched.

## Run the frontend

Start PostgreSQL and the API first, with the seed data loaded (see [Run the backend](#run-the-backend)). Then, with Node 22 or newer:

```
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. To vote, register first (next section), then sign in.

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
| `POST /api/auth/extend` | Starts a new full session. Called only when the voter chooses Keep voting |
| `POST /api/auth/logout` | Ends the session |
| `GET /api/ballot` | The voter's ballot paper and a single-use ballot token, once per election (SR-03) |
| `POST /api/ballot/submit` | Accepts the ranked ballot once and returns a receipt code. The same token again returns the same receipt (SR-03) |

Errors come back as `{"detail": "<reason>"}`:

- Sign in and voting: `invalid_credentials` and `not_signed_in` (401), `too_many_requests` (429), `not_a_voter` and `not_enrolled` (403), `no_open_election` (404), `already_voted` (409), `invalid_ballot` and `ballot_expired` (400).
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

## Settings

### Frontend

Optional. The defaults work as they are. To change them, copy `frontend/.env.example` to `frontend/.env`.

| Variable | Purpose | Default |
|---|---|---|
| `VITE_SESSION_MINUTES` | Length of a voting session. The voter is warned 1 minute before it ends. Keep it equal to `SESSION_MINUTES` | `10` |
| `VITE_API_TARGET` | Where the dev server forwards `/api` requests | `http://127.0.0.1:8000` |

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
| `SESSION_MINUTES` | How long a signed-in session lasts. Keep it equal to `VITE_SESSION_MINUTES` | `10` |
| `SECRET_KEY` | Root secret for field encryption and keyed hashes, at least 32 characters. Required | none |
| `MAX_FAILED_ATTEMPTS`, `LOCK_MINUTES`, `MFA_PENDING_MINUTES`, `RATE_LIMIT_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS`, `COOKIE_SECURE` | Sign-in lockout, rate limit and cookie settings. See [SR-01](#sr-01-authentication-and-rate-limiting) | `5`, `15`, `5`, `20`, `300`, `true` |
| `ROLL_PUBLIC_KEY_PATH`, `MIN_VOTING_AGE` | The roll's Ed25519 public key, and the minimum age on polling day. See [SR-02](#sr-02-roll-signing-and-eligibility) | `backend/keys/roll_public.pem`, `18` |
| `BALLOT_TOKEN_MINUTES` | How long a ballot token stays usable after it is issued. See [SR-03](#sr-03-single-ballot-per-elector) | `10` |

The fixed limits (registration time, wrong-code limits, rate limits, password length) are named constants in `backend/app/config.py`.

Never commit a real `.env` file. Only `.env.example` belongs in Git.

## Frontend security notes

- The browser never decides anything that matters. The rules in `src/lib/ballotRules.ts` and `src/lib/registerRules.ts` only give quick feedback, and the server repeats every check.
- Nothing is stored in `localStorage` or `sessionStorage`. The ballot token, selections and registration details live in memory and are cleared on submit, sign out, session timeout and leaving the register screen.
- Sign in and registration step 1 each show one generic message for every failure, so the screen never reveals which detail was wrong, or who is on the roll.
- Passwords are cleared from the page as soon as they are sent. The authenticator secret and QR code exist only while step 3 is on screen.
- The session timer counts down from sign in. Ordinary activity does not reset it. Only the voter choosing Keep voting in the warning calls `POST /api/auth/extend`, and only that call extends the server session.
- The receipt screen signs itself out after 60 seconds, for shared terminals.
- Fonts are bundled with the app (no font CDN), and the QR code is drawn in the browser, so the page makes no third-party requests.
- Sessions live in `HttpOnly`, `SameSite=Strict` cookies, so page scripts cannot read them and other sites cannot send them. The frontend and API are served from one origin through the dev server's proxy.

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

- Ballots are stored as plain JSON in the `ciphertext` column, and ballot definitions are not signed yet.
- A ballot holds no voter and no time, but it is stored in the same transaction that marks the voter. Someone with direct access to the database could match the two through PostgreSQL's internal transaction ids. A later stage should store ballots separately or in shuffled batches.
- The rate limiter keeps its counts in memory, so they reset when the API restarts and are not shared between several API processes. Behind the dev server's proxy every request comes from `127.0.0.1`, so the per-IP limit counts all users together.
- There is no CSRF token yet. `SameSite=Strict` cookies are the only protection. The session cookie is marked `Secure` unless `COOKIE_SECURE=false` (the local setting); the registration cookie is not marked `Secure` yet.
- Docker Compose passes all of `backend/.env` into the database container, including `SECRET_KEY`, which the database does not need.
- The receipt code is random and stored only on the used token row (SR-03). There is no way for a voter to check it yet.

## SR-01: authentication and rate limiting

Every elector must pass two steps before any voting route opens:

1. `POST /api/auth/login`: the password is checked against its Argon2id hash. Success starts a session at stage `mfa_pending`, which lasts `MFA_PENDING_MINUTES` and opens nothing except step 2.
2. `POST /api/auth/verify`: a 6-digit TOTP code from the authenticator app, from the current 30-second step or one either side. Each step's code works once. Success deletes the pending session and starts a new `authenticated` session under a new token.

`GET /api/ballot`, `POST /api/ballot/submit` and `POST /api/auth/extend` accept only an unexpired `authenticated` session. A pending session gets `401`.

| Setting | Default | Effect |
|---|---|---|
| `MAX_FAILED_ATTEMPTS` | `5` | Failed attempts in a row, at either step, before the account locks. A full sign in resets the count |
| `LOCK_MINUTES` | `15` | How long the account stays locked. The count starts again once the lock ends |
| `MFA_PENDING_MINUTES` | `5` | Time allowed between step 1 and step 2 |
| `RATE_LIMIT_ATTEMPTS` | `20` | Sign-in requests (both steps together) allowed per client IP in each window |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | Length of that window |
| `COOKIE_SECURE` | `true` | Marks the `session` cookie `Secure`. `backend/.env.example` sets it to `false` because the local demo runs on `http://localhost` |

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

**Issue** (`GET /api/ballot`). First the SR-01 signed-in session, then the SR-02 eligibility check. Then, in one transaction, the elector's row is inserted into `voter_participation` with state `issued` (`INSERT ... ON CONFLICT DO NOTHING`). If the row already exists, the elector already has a token or has voted: the answer is `409 already_voted` and nothing is issued. Otherwise the server creates a token of 256 random bits (`secrets.token_urlsafe(32)`), stores only its SHA-256 (hex) and an expiry `BALLOT_TOKEN_MINUTES` (10) minutes away, and returns the token once in `ballot_token`. The token itself is never stored or logged.

**Accept** (`POST /api/ballot/submit`). Again, the signed-in session and eligibility come first. Then, in one transaction:

1. lock the elector's participation row (`SELECT ... FOR UPDATE`), then the token row, always in that order;
2. reject an unknown or altered token (`400 invalid_ballot`);
3. if the token was already used, return the first answer again (`200`, same receipt reference) and store nothing;
4. reject an expired token (`400 ballot_expired`);
5. reject an elector who is not `issued`: `409 already_voted` if they have voted, `400 invalid_ballot` if they were never issued a ballot;
6. check the ballot content as before;
7. consume the token with one conditional `UPDATE` that must change exactly one row, recording when it was used and a random receipt reference;
8. store the ballot and mark the elector `voted`, then commit.

Any failure rolls everything back: a token is never used without a ballot, and a ballot never exists without the elector marked voted. A token stays unused after a rejected ballot, so the voter can correct it and submit again.

**Reloading the ballot page loses the token.** The token is returned once and lives only in the page's memory, and a second ballot request gets `already_voted`. The same happens if the 10 minutes pass. During development, clear the reviewer's `issued` state with:

```
python -m scripts.seed --reset-participation
```

It refuses once the reviewer has voted, because a cast ballot cannot be undone by design. Only `python -m scripts.seed --reset` (all data) starts that over. Each reset is audited as `ELECTOR_RESET`. There is no API endpoint or staff screen for it.

**Unlinked tables.** `voter_participation` (roll entry, election, state) has no timestamp. `ballot_tokens` (id, election, hash, expiry, when used, receipt reference) has no elector and no issue time. `ballots` (id, election, division, content) has no token, no reference and no time. So the database cannot match a ballot to a token, or a token to an elector. The receipt reference on the used token row is the only handle, and it points at no ballot.

**Audit.** `BALLOT_TOKEN_ISSUED`, `BALLOT_ACCEPTED`, `BALLOT_REPLAY_BLOCKED`, and `BALLOT_TOKEN_REJECTED` with a reason (`invalid`, `expired`, `wrong_state`), each with the account and the event only. No token, hash, receipt reference or ballot content.

Run the SR-03 tests, inside `backend/` with PostgreSQL running:

```
pytest tests/test_sr03_single_ballot.py -v
```

Design only, not implemented:

- Paper and absent-vote channels. They would mark the same `voter_participation` row, so an elector who voted on paper could not vote online, and the reverse.
- Staff screens for resetting an elector.
- Binding the token to the elector. A token works for any eligible elector who holds it, and the participation row still allows only one ballot each.

## Folder layout

```
backend/             FastAPI app, Alembic migrations, seed script and tests
frontend/            React app
docs/                MANUAL.md (files and how to run the app); requirements and design notes later
docker-compose.yml   PostgreSQL 16 for local development
```
