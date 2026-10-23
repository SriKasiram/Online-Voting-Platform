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
9. **Session reset (SR-15).** The frontend is built without demo values for `VITE_IDLE_SECONDS`, `VITE_IDLE_WARNING_SECONDS`, `VITE_RECEIPT_SECONDS` and `VITE_RESET_LOGOUT_TIMEOUT_MS` (defaults 90, 30, 60 and 3000), and `docs/MANUAL.md` section 11 still passes.
10. **Audit log (required, SR-16).** Run `pytest -m audit_capture`; run `python -m scripts.audit_checkpoint` and `python -m scripts.verify_audit`; both must pass; attach the output.
    - Run all three inside `backend/`, the two scripts against the release database.
    - The scripts must exit with code 0, the second ending in `SR-16 audit verification: PASS`. Record the audit head hash it prints in the release record.
11. **Monthly audit capture (SR-16).** Check that the monthly audit-capture workflow passed this month: the **Audit capture** workflow in GitHub Actions.
    - If it has not run this month, run it by hand: Actions, Audit capture, Run workflow.
    - Scheduled workflows run only on the default branch.
12. **House count (SR-17).** Before any count: verify_chain and verify_audit must pass. Run python -m scripts.count_house only after polls close and the final seal. A refusal must be investigated, never bypassed.
    - Inside `backend/`: `python -m scripts.verify_chain --election <id>` and `python -m scripts.verify_audit` must both exit with code 0.
    - Then run `python -m scripts.count_house --election <id>`. Attach its output and the result file (`exports/house_result_<id>.json`) to the release record.
    - A `REFUSED: <code>` stops the count with no result. There is no way to skip a check.
13. **Signed result release (SR-18).** Results leave the platform only through python -m scripts.release_results. After each release, verify it as a recipient would: fetch the key from /api/public/results-key, compare the fingerprint, run scripts/verify_release.py (VALID). Never edit a release folder; a correction is a new version.
    - Run `python -m scripts.release_results --election <id>` inside `backend/`. Record the version and the dataset SHA-256 it prints.
    - Copy the release folder somewhere else, fetch the key from `https://<server>/api/public/results-key`, and check its fingerprint against the one published.
    - Then run `python verify_release.py --dataset result.json --signature result.json.sig --public-key results_public.pem --expected-fingerprint <fingerprint>`. It must print `VALID`. Attach its output to the release record.
14. **Backups and recovery test (required, SR-20).** Take a backup before polls open (--label before_open) and at the close of polls (--label close). Run python -m scripts.recovery_test --reset-target quarterly and before each election; all checks must pass; attach the output.
    - Inside `backend/`: `python -m scripts.backup_db --label before_open` before polls open, and `python -m scripts.backup_db --label close` at the close of polls. Record each backup id it prints.
    - `python -m scripts.recovery_test --reset-target` must end in `PASS: all checks passed` and exit with code 0: `time`, `zero_loss` and `reconciliation` all PASS. A FAIL or a REFUSED blocks the election until it is explained.
    - Keep a copy of `BACKUP_KEY_FILE` apart from the backups, and never with the SR-11 ballot key. The backups (`backend/backups/`) and the key are never in the repository.
