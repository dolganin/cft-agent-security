"""New repair campaigns require current, evidence-backed case confirmations."""
import json
from types import SimpleNamespace

from app.single_pass_measurement import select_families


def test_detection_and_unsupported_verdict_do_not_admit_a_repair(tmp_path):
    (tmp_path / "development-agent.json").write_text(json.dumps({"cases": [
        {"case_id": "JS-SQL-001", "detected": True, "confirmation_supported": True},
        {"case_id": "JS-REDIRECT-001", "detected": True, "confirmation_supported": False},
    ]}))
    (tmp_path / "holdout-agent.json").write_text(json.dumps({"cases": []}))
    families = [SimpleNamespace(id="sql-search", case_ids=["JS-SQL-001"]),
                SimpleNamespace(id="redirect-allowlist", case_ids=["JS-REDIRECT-001"]),
                SimpleNamespace(id="missing", case_ids=["unknown"])]
    rows = select_families(tmp_path, families)
    assert [row["current_confirmed"] for row in rows] == [True, False, False]
    assert rows[0]["current_case_evidence"]["JS-SQL-001"]["confirmation_supported"]
