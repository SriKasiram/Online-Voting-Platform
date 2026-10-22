# Release checklist

Work through every step, in order, before a release. A release needs every required step done, and its output kept with the release record.

1. **Tests (required).** CI is green for the release commit. To check by hand:
   - inside `backend/`, `pytest` passes;
   - inside `frontend/`, `npm run typecheck`, `npm test`, `npm run build` and `npm audit --audit-level=high` all pass.
2. **Migrations.** Inside `backend/`, run `alembic upgrade head` against the release database.
3. **Ballot storage audit (required, SR-11).** Run `python -m scripts.audit_ballots` against the release database. It must exit with code 0. Attach the output to the release record.
   - Run it inside the git repository, with git installed, so the key check reports PASS rather than SKIPPED.
   - A FAIL blocks the release until the cause is found and fixed.
4. **Ballot key (SR-11).** `BALLOT_KEY_FILE` exists on the server, and a backup of it is kept separately from the database and its backups. It is never in the repository.
5. **TLS (SR-10).** The server starts with `python -m app.serve`, and `docs/MANUAL.md` section 6 still passes.
