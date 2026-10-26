"""
VULN-01, VULN-02: the whole path still works with the holding table, and the system columns link
nothing at the end of it, on the live database and on the restored copy. Real votes through the API,
then the returning officer's commands in order: seal (--final), count, signed release, and the SR-20
recovery test (a backup, a timed restore and its checks).
"""

import re
from contextlib import nullcontext
from pathlib import Path

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from test_sr17_count import CountedElection
# SR-18 and SR-20's own fixtures, reused: temporary keys, folders and the restore database
from test_sr18_release import releases_dir, results_keys  # noqa: F401
from test_sr20_backup import backup_key, backups_dir, restore_url, scripts_on_test_db, target, target_engine  # noqa: F401
from test_vuln01_ballot_linkage import HELD, physical_order, xmin_links
from app.stores import IDENTITY_TABLES
from scripts import audit_ballots, audit_separation, count_house, recovery_test, release_results, seal_ballots


class TestEndToEnd(CountedElection):
    def test_seal_count_release_backup_and_recovery_with_no_link_left(
        self, engine: Engine, db_session: Session, election, cast, clock, results_keys, releases_dir: Path,  # noqa: F811
        scripts_on_test_db, target_engine: Engine, tmp_path: Path, monkeypatch, capsys,  # noqa: F811
    ) -> None:
        """VULN-01, VULN-02: every step passes, and neither database has an xmin or disk-order link."""
        for order in ([0, 1, 2], [0, 1, 2], [1, 2, 0], [1, 2, 0], [2, 1, 0]):
            cast("Northgate", order)
        clock.advance(days=2)
        election_id = election.election.id
        for module in (count_house, release_results):
            monkeypatch.setattr(module, "engine", engine)
        monkeypatch.setattr(seal_ballots, "SessionLocal", lambda: nullcontext(db_session))
        monkeypatch.setattr(seal_ballots, "engine", engine)

        assert seal_ballots.main(["--election", str(election_id), "--final"]) == 0
        assert "Verification: PASS" in capsys.readouterr().out
        assert count_house.main(["--election", str(election_id), "--out", str(tmp_path / "result.json")]) == 0
        assert "Elected: Daniel Whitfield (Rural Alliance)" in capsys.readouterr().out
        assert release_results.main(["--election", str(election_id)]) == 0
        assert recovery_test.main(["--reset-target"]) == 0
        recovery = capsys.readouterr().out
        assert "5 ballots restored of 5; 1 chain(s) verified" in recovery and recovery.rstrip().endswith("PASS: all checks passed")

        with Session(target_engine) as restored:
            for database in (db_session, restored):
                assert xmin_links(database, election_id) == dict.fromkeys(sorted(IDENTITY_TABLES), 0)
                ids = physical_order(database, election_id)
                assert len(ids) == 5 and ids == sorted(ids)
                assert database.scalar(text(f"SELECT count(*) FROM {HELD}")) == 0
                separation = audit_separation.run_audit(database, [], tmp_path, tmp_path / "logs")
                assert [(c.name, c.status) for c in separation if c.status not in ("PASS", "SKIPPED")] == []
                assert {c.status for c in audit_ballots.run_audit(database, tmp_path)} <= {"PASS", "SKIPPED"}
        assert re.search(r"5 sealed ballot\(s\): no xmin shared", separation[-1].reason)
