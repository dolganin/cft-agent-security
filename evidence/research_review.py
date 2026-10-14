"""Evaluator-owned replay, outside model workspace, with explicit narrow proof scope."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from schemas.evidence import (
    Evidence,
    EvidenceAction,
    EvidenceArtifact,
    EvidenceObservation,
    EvidenceScope,
)
from security.source_paths import normalize_source_path


def review_source_claims(*, root, scope, progress, output):
    output = Path(output)
    if output.exists():
        raise FileExistsError("Independent review requires a fresh output directory")
    output.mkdir(parents=True)
    dispositions = []
    ledger = {x.action_id: x for x in progress.ledger}
    for ordinal, claim in enumerate(progress.source_claims):
        disposition = {"claim": claim.model_dump(mode="json"), "status": "review_pending",
                       "scope": "source_condition", "reason": "Missing independent proof"}
        try:
            file = normalize_source_path(claim.file, root)
            path = Path(root) / file
            expected = scope.source_files[file]
            raw = path.read_bytes()
            if len(raw) > 1048576 or sha256(raw).hexdigest() != expected.original_sha256:
                raise ValueError("Independent source binding changed")
            reads = [ledger[ref] for ref in claim.observation_refs]
            if not reads or any(x.tool != "read_source" or x.category != "observation" or x.observation.get("path") != file for x in reads):
                raise ValueError("Claim does not bind persisted source reads")
            lines = {int(line.partition(": ")[0]) for x in reads
                     for line in x.observation.get("content", "").splitlines()
                     if line.partition(": ")[1] and line.partition(": ")[0].isdigit()}
            if not 1 <= claim.line_start <= claim.line_end or claim.line_end - claim.line_start >= 160 or not set(range(claim.line_start, claim.line_end + 1)) <= lines:
                raise ValueError("Claim range was not read")
            request = {"source": raw.decode(), "file": file,
                       "line_start": claim.line_start, "line_end": claim.line_end}
            # Fixed read-only syntax parser, NOT target/model execution. No model argv.
            execution = subprocess.run([sys.executable, "-m", "evidence.research_source_reviewer"],
                input=json.dumps(request), capture_output=True, text=True, timeout=15, check=False,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})
            if execution.returncode or len(execution.stdout.encode()) > 65536:
                raise ValueError("Independent parser failed")
            observed = json.loads(execution.stdout)
            if path.read_bytes() != raw:
                raise ValueError("Source changed during independent review")
            disposition.update(observed)
            disposition["source_snapshot"] = scope.source_snapshot
            disposition["research_session_id"] = scope.session_id
            disposition["independent_runner"] = "fixed AST parser in fresh process; no model script"
        except (ValueError, KeyError, OSError, subprocess.TimeoutExpired):
            disposition["reason"] = "Source/read binding unavailable or independent parser failed"
        ref = output / f"review-{ordinal}.json"
        ref.write_text(json.dumps(disposition, indent=2) + "\n")
        dispositions.append(disposition)
    (output / "reviews.json").write_text(json.dumps(dispositions, indent=2) + "\n")
    return dispositions


def attach_source_review(state, reviews, output):
    """Never upgrade unrelated findings or manufacture runtime confirmation."""
    finding = state["finding"]
    digest_finding = any(word in (finding.rule_id + " " + finding.title).lower()
                         for word in ("md5", "sha1", "sha-1", "digest", "hash"))
    compatible = [r for r in reviews if digest_finding and r["claim"]["file"] == finding.file
                  and r["status"] in {"confirmed", "rejected"}
                  and finding.line_start is not None
                  and r["claim"]["line_start"] <= finding.line_start <= r["claim"]["line_end"]
                  and finding.provenance is not None
                  and finding.provenance.family == "weak-cryptography"]
    if not compatible:
        return state
    verdicts = {r["status"] for r in compatible}
    if len(verdicts) != 1 or state.get("status") == "policy_blocked":
        return state
    action, execution = state.get("proposed_action"), state.get("execution")
    if action is None or execution is None:
        return state
    # Review is tied to its actual source-read action, not the last generic script.
    ref = compatible[0]["claim"]["observation_refs"][0]
    history = next((x for x in state["action_history"] if x.action.id == ref and x.execution), None)
    if history is None:
        return state
    evidence_ref = str(Path(output) / "reviews.json")
    evidence = Evidence(id="source-review-" + sha256(evidence_ref.encode()).hexdigest()[:20],
        action_id=history.action.id, type="independent_source_review", source="static",
        summary="Independent AST evidence for the explicit weak-digest source condition only",
        verdict=compatible[0]["status"], reliability="high", hypothesis_id=state["hypothesis"].id,
        action=EvidenceAction(id=history.action.id, tool=history.action.tool, run_id=history.execution.run_id),
        observation=EvidenceObservation(kind="independent_source_review", facts={"review": compatible[0]}),
        scope=EvidenceScope(target=history.action.target, environment=history.action.environment,
                           description="Source-condition proof; runtime exploitability and impact unverified"),
        artifact_refs=[evidence_ref], artifacts=[EvidenceArtifact(ref=evidence_ref, role="other")])
    return {**state, "evidence": [*state["evidence"], evidence], "proposed_action": history.action,
            "execution": history.execution, "validation": history.validation,
            "status": evidence.verdict, "stop_reason": "terminal_evidence"}
