from __future__ import annotations

import copy
import json
from difflib import unified_diff

import pytest
import yaml
from pydantic import ValidationError

from agent.repository_scout import RepositoryScout
from evaluation import control_catalog as catalog
from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.control_patch import redirect_patch
from evaluation.control_workspace import patched_snapshot
from schemas.benchmark_controls import ControlCatalog, SafeControl
from schemas.discovery import ProjectDiscoveryResult
from schemas.scout import ScoutTurn
from tools.repository_source import RepositorySource


@pytest.fixture
def small_target(tmp_path, monkeypatch):
    files = {
        "data/static/challenges.yml":"- key: exampleChallenge\n  category: Injection\n",
        "data/static/codefixes/exampleChallenge.info.yml":"fixes:\n- id: 2\n  explanation: Exact bound parameter fixes the statement.\n",
        "data/static/codefixes/exampleChallenge_2_correct.ts":"query({value: input})\n",
        "routes/example.ts":"// vuln-code-snippet start exampleChallenge\nquery(input)\n// vuln-code-snippet end exampleChallenge\n",
    }
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    monkeypatch.setattr(catalog, "pinned_files", lambda root: sorted(files))
    return tmp_path


def test_discovery_is_deterministic_and_not_truth(small_target):
    first = catalog.discover(small_target)
    assert first == catalog.discover(small_target)
    candidate = first["candidates"][0]
    assert candidate["truth_validated"] is False
    assert candidate["explanation"] and candidate["source_anchors"][0]["start"] == 1
    assert candidate["reconciliation_required"] is True
    assert candidate["split"] == split_group(candidate["independence_group"], load_protocol().split)


def test_correct_filename_without_metadata_cannot_be_usable(small_target):
    (small_target / "data/static/codefixes/exampleChallenge.info.yml").write_text("fixes: []\n")
    result = catalog.discover(small_target)["candidates"][0]
    assert result["reason"] == "source_mismatch" and not result["truth_validated"]


def test_source_anchor_detects_changed_bytes(small_target):
    old = catalog.anchor(small_target, "routes/example.ts", 1, 3)
    (small_target / "routes/example.ts").write_text("// different\nquery(bound)\n// end\n")
    assert old != catalog.anchor(small_target, "routes/example.ts", 1, 3)


@pytest.fixture
def patch_input(tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    source = "first\nunsafe()\nlast\n"
    (original / "route.ts").write_text(source, newline="\n")
    after = source.replace("unsafe()", "safe()")
    diff = "".join(unified_diff(source.splitlines(True), after.splitlines(True), fromfile="a/route.ts", tofile="b/route.ts"))
    return original, source, diff


def test_patch_only_in_disposable_copy_original_bytes_unchanged(patch_input):
    original, source, diff = patch_input
    with patched_snapshot(original, "route.ts", diff, catalog.sha(source.encode()), catalog.sha(diff.encode())) as root:
        assert root != original and "safe()" in (root / "route.ts").read_text()
        assert (original / "route.ts").read_bytes() == source.encode()
        workspace = root
    assert not workspace.exists()
    assert (original / "route.ts").read_bytes() == source.encode()


@pytest.mark.parametrize("source_mismatch", [True, False])
def test_digest_mismatch_rejected_before_application(patch_input, source_mismatch):
    root, source, diff = patch_input
    source_sha, patch_sha = catalog.sha(source.encode()), catalog.sha(diff.encode())
    with pytest.raises(ValueError, match="digest mismatch"), patched_snapshot(root, "route.ts", diff,
            "0"*64 if source_mismatch else source_sha, patch_sha if source_mismatch else "0"*64):
        pytest.fail("Must reject before yielding")
    assert (root / "route.ts").read_bytes() == source.encode()


def test_patch_exception_still_cleans_copy(patch_input):
    root, source, diff = patch_input
    with pytest.raises(RuntimeError, match="experiment failed"), patched_snapshot(root, "route.ts", diff,
            catalog.sha(source.encode()), catalog.sha(diff.encode())) as copied:
        workspace = copied
        raise RuntimeError("experiment failed")
    assert not workspace.exists()


GATES = ["build","tests","start","smoke","reachable","legitimate_request","property_assertion",
         "fresh_state","cleanup","original_unchanged","snapshot_removed","owner_identity","other_identity",
         "owned_object","ownership","sessions_after"]


@pytest.mark.parametrize("gate", GATES)
def test_failed_precondition_never_safe(gate):
    evidence = dict.fromkeys(GATES, True)
    assert catalog.runtime_safe(evidence, role_dependent=True)
    evidence[gate] = False
    assert not catalog.runtime_safe(evidence, role_dependent=True)
    evidence[gate] = "true"
    assert not catalog.runtime_safe(evidence, role_dependent=True)


def test_invalid_identity_missing_object_and_http_denial_not_safe():
    assert not catalog.runtime_safe({"property_assertion":True, "http_status":403}, role_dependent=True)


def test_source_and_correct_answers_do_not_leak_to_scout(tmp_path):
    sources = {
        "routes/control.ts":"handler(req.params.id) // vuln-code-snippet vuln-line safeTwin\n",
        "data/static/codefixes/control_1_correct.ts":"SECRET_OFFICIAL_FIX_ANSWER\n",
        "benchmarks/controls.reviewed.yaml":"safe_expected_behaviour: SECRET_SAFE_LABEL\n",
    }
    for file, text in sources.items():
        path = tmp_path / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    inventory = ProjectDiscoveryResult(repository_root=tmp_path, project_files=list(sources))
    reader = RepositorySource(inventory)
    assert set(reader.lines) == {"routes/control.ts"}, reader.skipped

    class Client:
        def __init__(self):
            self.payloads = []

        def complete_model(self, **kwargs):
            self.payloads.append(kwargs["user_payload"])
            return ScoutTurn(stop=True)

    client = Client()
    RepositoryScout(client, max_turns=1).scout(inventory)
    payload = json.dumps(client.payloads)
    assert "handler(req.params.id)" in payload
    assert all(value not in payload for value in ["SECRET_OFFICIAL_FIX_ANSWER", "SECRET_SAFE_LABEL", "safeTwin", "vuln-code-snippet"])


@pytest.fixture
def reviewed():
    return yaml.safe_load((catalog.DIRECTORY / "controls.reviewed.yaml").read_text(encoding="utf-8"))


def test_reviewed_types_counts_and_independence(reviewed):
    parsed = ControlCatalog.model_validate(reviewed)
    assert len(parsed.controls) == 4
    assert [x.control_type for x in parsed.controls].count("original_safe") == 4
    assert [x.control_type for x in parsed.controls].count("patched_safe") == 0
    assert len({x.independence_group for x in parsed.controls}) == 4
    for control in parsed.controls:
        assert control.split == split_group(control.independence_group, load_protocol().split)
        assert not control.agent_verifiable_now


def test_safe_twin_group_uses_root_cause_not_positive_id(reviewed):
    generated = yaml.safe_load((catalog.DIRECTORY / "candidates.generated.yaml").read_text(encoding="utf-8"))
    twin = next(x for x in generated["candidates"] if x["challenge_key"] == "redirectChallenge")
    assert twin["independence_group"] == "juice-redirect-substring-allowlist"
    positive_compatibility_key = "juice-" + twin["root_cause_key"]
    assert twin["split"] == split_group(positive_compatibility_key, load_protocol().split)


@pytest.mark.parametrize("kind", ["original_safe", "patched_safe", "synthetic_safe"])
def test_control_origin_not_collapsed(reviewed, kind):
    value = copy.deepcopy(reviewed["controls"][0])
    value["control_type"] = kind
    if kind == "patched_safe":
        value.update(patch_reference="patches/control.patch", patch_sha256="a"*64, source_sha256="b"*64)
    assert SafeControl.model_validate(value).control_type == kind


def test_unknown_family_or_truth_field_rejected(reviewed):
    value = copy.deepcopy(reviewed["controls"][0])
    value["family"] = "scanner-silence"
    with pytest.raises(ValidationError):
        SafeControl.model_validate(value)
    value["family"] = "authorization"
    value["model_answer"] = "safe"
    with pytest.raises(ValidationError):
        SafeControl.model_validate(value)


def test_real_reset_proof_has_fresh_state_and_complete_cleanup(reviewed):
    for reference in {x["evidence_reference"] for x in reviewed["controls"] if x["validation_basis"] == "runtime"}:
        proof = json.loads((ROOT / reference).read_text())
        first, second = proof["cycles"]
        assert first["container"] != second["container"]
        assert first["baseline"] == second["baseline"]
        for cycle in proof["cycles"]:
            assert cycle["cleanup"] and cycle["snapshot_removed"] and cycle["original_unchanged"]
            assert all(x["passed"] for x in cycle["stages"].values())
            assert all(catalog.runtime_safe(x, role_dependent="owner_identity" in x) for x in cycle["properties"].values())


def test_official_redirect_fix_matches_source_and_digest():
    patch = redirect_patch(catalog.TARGET)
    assert patch["diff"].count("+    allowed = allowed || url === allowedUrl") == 1
    assert patch["patch_sha256"] == catalog.sha(patch["diff"].encode())
    assert "PRIVATE KEY" not in patch["diff"]


def test_real_failed_patch_not_published_as_safe(reviewed):
    exclusions = yaml.safe_load((catalog.DIRECTORY / "excluded.yaml").read_text(encoding="utf-8"))
    failed = next(x for x in exclusions["controls"] if "redirectChallenge-4" in x["id"])
    assert failed["disposition"] == "excluded" and failed["reason"] == "build_failure"
    assert all(x["control_type"] != "patched_safe" for x in reviewed["controls"])


def test_truth_only_proof_has_no_runtime_verdict(reviewed):
    from evaluation.control_source import orm_proof
    source = next(x for x in reviewed["controls"] if x["validation_basis"] == "source_review")
    assert source["runtime_eligibility"] == "truth_only" and not source["agent_verifiable_now"]
    proof = json.loads((ROOT / source["evidence_reference"]).read_text())
    assert proof == orm_proof(catalog.TARGET)
    assert "cycles" not in proof


def test_protocol_lock_and_v1_still_valid():
    protocol = load_protocol()
    assert protocol.target_commit == "5658473cf8814459bf89000ce373b20ed0b4eb37"
    assert catalog.sha((ROOT / "benchmarks/juice-shop-v20.2.0-v2/protocol.yaml").read_bytes()) == "565d4ebe6ff2f3c57b4892b653542873d07cc2f5521846d79e78394401795031"


def test_production_does_not_import_a03_truth():
    for directory in ["agent","app","tools","executor","validator"]:
        for file in (ROOT / directory).rglob("*.py"):
            source = file.read_text(encoding="utf-8")
            assert "evaluation.control_" not in source
            assert "controls.reviewed.yaml" not in source


def test_agent_projection_and_frozen_sast_do_not_receive_answers(tmp_path):
    from agent.llm_model import _reasoning_context
    from schemas.finding import Finding
    from schemas.target import TargetProfile
    finding = Finding(id="ordinary", source="semgrep", rule_id="ordinary", title="Observation",
        description="Source observation", file="routes/address.ts", line_start=18)
    state = {"finding":finding, "target_profile":TargetProfile.from_yaml(
        ROOT / "targets/juice-presentation.yaml", repository_path_override=tmp_path),
        "code_context":"AddressModel.findOne({where:{id:req.params.id}})",
        "safe_label":"SECRET_SAFE_LABEL", "correct_fix":"SECRET_OFFICIAL_FIX_ANSWER",
        "control_type":"original_safe", "expected_rejection":"SECRET_EXPECTED_REJECTION"}
    prompt = json.dumps(_reasoning_context(state))
    assert all(value not in prompt for value in ["SECRET_SAFE_LABEL", "SECRET_OFFICIAL_FIX_ANSWER", "SECRET_EXPECTED_REJECTION", "original_safe"])
    rules = yaml.safe_load((ROOT / "docs/demo/semgrep.yaml").read_text(encoding="utf-8"))
    included = {file for rule in rules["rules"] for file in rule["paths"]["include"]}
    assert included == {"routes/login.ts", "routes/search.ts", "server.ts"}


@pytest.mark.parametrize("change", ["split", "anchor", "evidence", "patch", "group"])
def test_catalog_rejects_damaged_bindings(tmp_path, monkeypatch, reviewed, change):
    import shutil
    directory = tmp_path / "controls"
    shutil.copytree(catalog.DIRECTORY, directory)
    value = copy.deepcopy(reviewed)
    control = value["controls"][0]
    if change == "split":
        control["split"] = "development" if control["split"] == "holdout" else "holdout"
    elif change == "anchor":
        control["source_anchors"][0]["sha256"] = "0"*64
    elif change == "evidence":
        control["evidence_sha256"] = "0"*64
    elif change == "patch":
        control["control_type"] = "patched_safe"
    else:
        control["root_cause_key"] = "unrelated"
    catalog.write_yaml(directory / "controls.reviewed.yaml", value)
    generated = yaml.safe_load((directory / "candidates.generated.yaml").read_text(encoding="utf-8"))
    monkeypatch.setattr(catalog, "pinned_files", lambda root: [])
    monkeypatch.setattr(catalog, "discover", lambda root: generated)
    with pytest.raises((ValueError, ValidationError)):
        catalog.validate(catalog.TARGET, directory)
