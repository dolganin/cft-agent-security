from types import SimpleNamespace

import pytest

from app.research_score import runtime_result_paths
from schemas.finding import Finding, FindingProvenance


def test_runtime_replay_reads_both_campaign_verification_layouts(tmp_path):
    old = tmp_path / "campaign/canonical-verification/0/result.json"
    early = tmp_path / "campaign/preverification/checks/0/result.json"
    old.parent.mkdir(parents=True)
    early.parent.mkdir(parents=True)
    old.write_text("{}")
    early.write_text("{}")
    assert runtime_result_paths(tmp_path) == sorted([old, early])


def test_runtime_job_can_cover_only_same_bound_source_observations():
    from app.research_score import _validated_job_finding_ids

    binding = SimpleNamespace(source_files={"routes/login.ts": "b" * 64},
        source_file="routes/login.ts", line_start=34, line_end=34, service="juice",
        anchor_sha256="c" * 64, family="sql-injection")

    def finding(identifier, rule, *, line=34, anchor="c"):
        provenance = FindingProvenance(family="sql-injection", fingerprint="a" * 64,
            normalized_file="routes/login.ts", file_sha256="b" * 64,
            anchor_sha256=anchor * 64, anchor_status="source_bound")
        return Finding(id=identifier, source="sast", rule_id=rule, title="SQL finding",
            description="Same source sink", file="routes/login.ts", line_start=line,
            line_end=line, service="juice", provenance=provenance)

    primary = finding("primary", "javascript.express.security.injection.tainted-sql-string.tainted-sql-string")
    alias = finding("alias", "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection")
    findings = {item.id: item for item in (primary, alias)}
    review = {"job_finding_ids": ["primary", "alias"]}

    assert _validated_job_finding_ids("primary", review, binding, findings) == ["primary", "alias"]
    findings["neighbor"] = finding("neighbor", alias.rule_id, line=35)
    review["job_finding_ids"] = ["primary", "neighbor"]

    with pytest.raises(ValueError, match="unrelated observation"):
        _validated_job_finding_ids("primary", review, binding, findings)
