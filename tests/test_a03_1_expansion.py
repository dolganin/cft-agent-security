from __future__ import annotations

import copy
import json

import pytest
import yaml
from pydantic import ValidationError

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.control_catalog import DIRECTORY, TARGET, sha
from evaluation.control_expansion import EXPANSION, POSITIVES, preserve, reconcile, runtime_proof
from evaluation.control_expansion_runtime import TESTS, classify_tests, make_patch
from evaluation.control_expansion_sources import SPECS, source_proof
from evaluation.control_workspace import patched_snapshot
from schemas.benchmark_control_expansion import ExpandedControl
from schemas.discovery import ProjectDiscoveryResult
from tools.repository_source import RepositorySource


def test_existing_four_and_all_protected_inputs_unchanged():
    preserve()
    old=yaml.safe_load((DIRECTORY/"controls.reviewed.yaml").read_text(encoding="utf-8"))
    assert [c["id"] for c in old["controls"]]==["JS-SAFE-AUTHZ-001","JS-SAFE-AUTHZ-002","JS-SAFE-DATA-001","JS-SAFE-SQL-001"]


@pytest.fixture
def positives():
    return yaml.safe_load(POSITIVES.read_text(encoding="utf-8"))["cases"]


def twin(positives):
    positive=next(p for p in positives if p["id"]=="JS-REDIRECT-001")
    return {"id":"JS-SAFE-REDIRECT-101","independence_group":positive["independence_group"],
            "split":positive["split"],"related_root_cause_key":positive["root_cause_key"],"related_positive_case_ids":[positive["id"]]}


def test_reconciliation_is_deterministic_and_exact(positives):
    control=twin(positives)
    first=reconcile([control],positives)
    assert first==reconcile([control],list(reversed(positives)))
    assert first[0]["status"]=="matched"
    assert control["split"]==split_group(control["independence_group"],load_protocol().split)


@pytest.mark.parametrize("field",["independence_group","split","related_root_cause_key","related_positive_case_ids"])
def test_reconciliation_mismatch_rejected(positives,field):
    control=twin(positives)
    control[field]=["missing"] if field=="related_positive_case_ids" else "mismatch"
    with pytest.raises(ValueError,match="mismatch"):
        reconcile([control],positives)


def test_original_source_oracles_deterministic():
    for spec in SPECS:
        assert source_proof(TARGET,spec)==source_proof(TARGET,spec)
        assert source_proof(TARGET,spec)["runtime_verdict"] is None


def test_source_gate_mutation_is_not_safe(tmp_path):
    spec=SPECS[0]
    file=tmp_path/spec["file"]
    file.parent.mkdir()
    file.write_text((TARGET/spec["file"]).read_text(encoding="utf-8").replace("user.password !== security.hash(password)","false"))
    with pytest.raises(ValueError):
        source_proof(tmp_path,spec)


@pytest.fixture
def vulnerable_output():
    file=DIRECTORY/"evidence/redirect-rejected/cycle-1/tests.json"
    return json.loads(file.read_text(encoding="utf-8"))["stdout"]


def test_case_specific_vulnerable_expectations_have_explicit_evidence(vulnerable_output):
    result=classify_tests(vulnerable_output,1,"redirect")
    assert result["accepted"] and result["exceptions"]==TESTS
    assert len(result["exceptions"])==2
    assert result["summary"]["counts"]["passed"]==411


@pytest.mark.parametrize("mutation",["functional","additional","cancelled","wrong_candidate","missing_summary"])
def test_functional_unknown_or_extra_failure_blocks_patch(vulnerable_output,mutation):
    text=vulnerable_output
    candidate="redirect"
    if mutation=="functional":
        text=text.replace("returns true for URLs containing allowed URLs","normal search returns products")
    elif mutation=="additional":
        text+=' FAIL legitimate search: AssertionError'
    elif mutation=="cancelled":
        text=text.replace('"cancelled":0','"cancelled":1')
    elif mutation=="wrong_candidate":
        candidate="nosql"
    else:
        text="Unknown test output"
    assert not classify_tests(text,1,candidate)["accepted"]


def test_no_global_test_ignore_list():
    source=(ROOT/"evaluation/control_expansion_runtime.py").read_text(encoding="utf-8")
    assert 'candidate == "redirect"' in source
    assert "test-name-pattern" not in source
    assert "test-skip-pattern" not in source
    assert {x["file"] for x in TESTS}=={"test/server/insecurity.unit.test.ts","test/server/redirect.unit.test.ts"}


def test_empty_test_suite_does_not_pass_validation():
    output='TEST SUMMARY '+json.dumps({"counts":{"tests":0,"passed":0,"skipped":0,"failed":0,"cancelled":0}})
    assert not classify_tests(output,0,"nosql")["accepted"]


def test_correct_filename_never_grants_reviewed_truth():
    triage=yaml.safe_load((EXPANSION/"triage.yaml").read_text(encoding="utf-8"))
    assert len(triage["selected_candidates"])==6
    assert all(c["truth_validated"] is False for c in triage["selected_candidates"])
    assert len(triage["unselected_candidates"])==29


@pytest.fixture
def report():
    return json.loads((EXPANSION/"evidence/nosql/report.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("gate",["oracle","cleanup","original_unchanged","snapshot_removed","foreign_container"])
def test_runtime_failure_never_safe(report,gate):
    damaged=copy.deepcopy(report)
    if gate=="foreign_container":
        damaged["cycles"][0]["container"]="foreign-container"
    else:
        damaged["cycles"][0][gate]=False
    with pytest.raises(ValueError):
        runtime_proof(damaged,"nosql")


@pytest.mark.parametrize("stage",["prepare","build","tests","start","smoke"])
def test_failed_required_stage_blocks_patch(report,stage):
    damaged=copy.deepcopy(report)
    damaged["cycles"][0]["stages"][stage]["accepted"]=False
    with pytest.raises(ValueError):
        runtime_proof(damaged,"nosql")


@pytest.mark.parametrize("gate",["identity","resource_exists","legitimate","negative_assertion","post_available","post_identity"])
def test_missing_identity_object_or_availability_blocks_patch(report,gate):
    damaged=copy.deepcopy(report)
    damaged["cycles"][0]["oracle_result"][gate]=False
    with pytest.raises(ValueError):
        runtime_proof(damaged,"nosql")


def test_patch_is_disposable_and_single_source_scope():
    patch=make_patch(TARGET,"nosql")
    before=sha((TARGET/patch["file"]).read_bytes())
    assert patch["diff"].count("--- a/")==1 and patch["diff"].count("+++ b/")==1
    with patched_snapshot(TARGET,patch["file"],patch["diff"],patch["source_sha256"],patch["patch_sha256"]) as isolated:
        assert "typeof req.body.id !== 'string'" in (isolated/patch["file"]).read_text(encoding="utf-8")
        assert sha((TARGET/patch["file"]).read_bytes())==before
        copy_path=isolated
    assert not copy_path.exists() and sha((TARGET/patch["file"]).read_bytes())==before


def test_fixture_answer_tests_excluded_from_source_reader():
    root=EXPANSION/"synthetic"
    reader=RepositorySource(ProjectDiscoveryResult(repository_root=root,project_files=["fixtures.py","tests/check_fixture.py"]))
    assert set(reader.lines)=={"fixtures.py"}
    text="\n".join(reader.lines["fixtures.py"])
    assert "run_assertions" not in text and "html_text" not in text


def test_expansion_truth_not_in_production_imports():
    for folder in ["agent","app","executor","tools","validator"]:
        for file in (ROOT/folder).rglob("*.py"):
            assert "control_expansion" not in file.read_text(encoding="utf-8")


def test_all_slices_and_source_only_semantics_preserved():
    rows=yaml.safe_load((EXPANSION/"controls.reviewed.yaml").read_text(encoding="utf-8"))["controls"]
    controls=[ExpandedControl.model_validate(row) for row in rows]
    assert {x.control_type for x in controls}=={"original_safe","patched_safe","synthetic_safe"}
    for control in controls:
        assert control.runtime_verdict is None and not control.agent_verifiable_now
        if control.validation_basis=="source_review":
            assert control.control_type=="original_safe"
    row=copy.deepcopy(rows[0])
    row["runtime_verdict"]="rejected"
    with pytest.raises(ValidationError):
        ExpandedControl.model_validate(row)


def test_a01_a02_v1_frozen_and_valid():
    preserve()
    assert load_protocol().target_commit=="5658473cf8814459bf89000ce373b20ed0b4eb37"


def test_protocol_lock_lf_checkout_preserves_content_binding(tmp_path,monkeypatch):
    import evaluation.control_expansion as module
    path="benchmarks/juice-shop-v20.2.0-v2/protocol.lock.json"
    copy_path=tmp_path/"protocol.lock.json"
    copy_path.write_bytes((ROOT/path).read_bytes().replace(b"\r\n",b"\n"))
    original=module.safe_file
    monkeypatch.setattr(module,"safe_file",lambda root,file:copy_path if file==path else original(root,file))
    preserve()
    copy_path.write_bytes(copy_path.read_bytes()+b" ")
    with pytest.raises(ValueError,match="input changed"):
        preserve()


def test_two_real_cycles_have_independent_state_and_original_integrity(report):
    first,second=report["cycles"]
    assert first["container"]!=second["container"]
    assert all(c["original_unchanged"] and c["cleanup"] and c["snapshot_removed"] for c in report["cycles"])
    runtime_proof(report,"nosql")
