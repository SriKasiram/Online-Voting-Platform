# Release checklist

Work through every step, in order, before a release. A release needs every required step done, and its output kept with the release record.

1. **Tests (required).** CI is green for the release commit. To check by hand:
   - inside `backend/`, `pytest` passes;
   - inside `frontend/`, `npm run typecheck`, `npm test`, `npm run build` and `npm audit --audit-level=high` all pass.
2. **Migrations.** Inside `backend/`, run `alembic upgrade head` against the release database.
3. **Ballot storage audit (required, SR-11).** Run `python -m scripts.audit_ballots` against the release database. It must exit with code 0. Attach the output to the release record.
   - Run it inside the git repository, with git installed, so the key check reports PASS rather than SKIPPED.
   - A FAIL blocks the release until the cause is found and fixed.
4. **Separation audit before each election (required, SR-12).**
   - First make the two separate backup dumps (identity side and ballot side) and the ballot export, as described in the README's SR-12 section.
   - Then run `python -m scripts.audit_separation --file <each backup and export file>` against the release database. It must exit with code 0, ending in `SR-12 separation audit: PASS`. Attach the output to the release record.
   - Store and encrypt the two dumps separately, never in the repository.
5. **Ballot chain (required, SR-13).** For each election, seal what is left (`python -m scripts.seal_ballots --election <id> --final` once polls have closed).
   - Then run `python -m scripts.verify_chain --election <id>`. It must exit with code 0. Attach the output and record the head hash it prints in the release record.
   - Keep the checkpoint files (`backend/checkpoints/`) with the release record, apart from the database.
6. **Ballot key (SR-11).** `BALLOT_KEY_FILE` exists on the server, and a backup of it is kept separately from the database and its backups. It is never in the repository.
7. **TLS (SR-10).** The server starts with `python -m app.serve`, and `docs/MANUAL.md` section 6 still passes.
8. **Acceptance confirmation (SR-14).** `ACCEPT_TIMEOUT_SECONDS` on the server is between 1 and 9 (the server refuses to start otherwise), and `docs/MANUAL.md` section 10 still passes: the confirmation holds only the reference, and a held lock gets `try_again` with nothing stored.
