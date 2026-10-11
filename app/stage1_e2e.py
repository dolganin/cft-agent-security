"""One-command real Docker Juice Shop fix verification. No simulated verdicts."""
from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from app.demo import PATCH_FINDING, PATCH_REVIEW_POLICY, PROFILE
from fix_verification.review import prepare_patch_review, validate_sequelize_search_proposal
from fix_verification.service import FixVerificationService
from fix_verification.workspace import digest, original_commit, snapshot, tree_digest
from schemas.fix import PatchReviewArtifact, ProposedPatch
from schemas.report import FinalReport, ReportFinding, VerificationSummary
from schemas.target import (
    TargetFixConfig,
    TargetProfile,
    is_immutable_image_id,
    is_repository_digest,
)
from security.error_redaction import redact_error_message
from tools.repository_source import _safe_line

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
ROOT = Path(__file__).resolve().parents[1]


def _command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False, shell=False)
    if result.returncode:
        raise RuntimeError(redact_error_message(result.stderr))
    return result.stdout.strip()


def _inspect_image(value: str) -> dict:
    records = json.loads(_command(["docker", "image", "inspect", value]))
    if not isinstance(records, list) or not records or not isinstance(records[0], dict):
        raise ValueError("Docker image inspect returned no record for: " + value)
    return records[0]


def pinned_image(value: str) -> str:
    """Resolve only already installed images; never pull during verification.

    Repository digests and full image IDs are accepted as-is after inspect proves
    the image is present. A locally provisioned tag without RepoDigests resolves to
    the full immutable image ID reported by inspect; no digest is ever synthesized
    and no mutable tag can reach the runtime.
    """
    candidate = value.strip()
    if not candidate or any(character.isspace() for character in candidate):
        raise ValueError("Image reference must be one non-empty operator token")
    if candidate.startswith("sha256:") and not is_immutable_image_id(candidate):
        raise ValueError("Image ID must be the full sha256:<64 lowercase hex> form: " + candidate)
    if "@sha256:" in candidate and not is_repository_digest(candidate):
        raise ValueError("Repository digest must be name@sha256:<64 lowercase hex>: " + candidate)
    record = _inspect_image(candidate)
    image_id = record.get("Id")
    if is_immutable_image_id(candidate):
        if image_id != candidate:
            raise ValueError("Pinned image ID does not match the inspected image")
        return candidate
    if is_repository_digest(candidate):
        return candidate
    digests = sorted(item for item in (record.get("RepoDigests") or [])
                     if isinstance(item, str) and is_repository_digest(item))
    if digests:
        return digests[0]
    if is_immutable_image_id(image_id):
        return image_id
    raise ValueError("Image has no immutable repository digest or image ID: " + candidate)


def digest_pinned_worker_image(value: str) -> str:
    """Worker images feed SandboxPolicy, which still requires a repository digest."""
    reference = pinned_image(value)
    if not is_repository_digest(reference):
        raise ValueError(
            "Worker image has no repository digest; the Docker sandbox policy requires "
            "name@sha256:<64 hex>, so a digest-less local worker build is not accepted"
        )
    return reference


class IntegrationPatchClient:
    """Reproducible operator SQL proposal, submitted to normal strict PatchReview."""
    def __init__(self, source: str):
        clean = "\n".join(_safe_line(line) for line in source.splitlines()) + "\n"
        old = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)"
        new = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`, { replacements: { criteria: `%${criteria}%` } })"
        if clean.count(old) != 1:
            raise ValueError("Pinned SQL source no longer matches the integration proposal")
        modified = clean.replace(old, new)
        modified = "\n".join(line.rstrip() if new in line else line
                             for line in modified.splitlines()) + "\n"
        self.proposal = ProposedPatch(finding_id=PATCH_FINDING,
            rationale="Bind LIKE values through Sequelize replacements; retain filtering and sort order.",
            unified_diff="".join(difflib.unified_diff(clean.splitlines(True), modified.splitlines(True),
                                                    fromfile="a/routes/search.ts", tofile="b/routes/search.ts")))

    def complete_model(self, **kwargs):
        if kwargs.get("operation") != "propose_patch":
            raise ValueError("Integration client supports only the reviewed patch proposal")
        return self.proposal


def run(args) -> int:
    _command(["docker", "info", "--format", "{{.ServerVersion}}"])
    worker_image = digest_pinned_worker_image(args.worker_image or os.getenv("CFT_SANDBOX_IMAGE") or "python:3.12-alpine")
    fix_image = pinned_image(args.fix_image or os.getenv("CFT_FIX_IMAGE") or "cft-fix-juice:stage1")
    os.environ["CFT_SANDBOX_IMAGE"] = worker_image
    profile = TargetProfile.from_yaml(PROFILE, repository_path_override=args.target)
    root = profile.repository_path
    if root is None or not root.is_dir() or original_commit(root) != COMMIT:
        raise ValueError("A checkout of the exact Juice Shop v20.2.0 commit is required")
    status = _command(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise ValueError("Original target must be clean; unexpected tracked/untracked changes exist")
    profile = profile.model_copy(update={"fix_verification": TargetFixConfig(
        image=fix_image, service="juice", source_commit=COMMIT)})
    directory = Path(args.output_dir).resolve() / ("stage1-" + uuid4().hex)
    if directory.is_relative_to(root):
        raise ValueError("Output directory must be outside the original target")
    directory.mkdir(parents=True)
    (directory / "images.json").write_text(json.dumps({"worker": worker_image, "fix": fix_image}, indent=2), encoding="utf-8")
    (directory / "target-profile.json").write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    source = (root / "routes/search.ts").read_bytes()
    integrity = {"commit": original_commit(root), "source_sha256": digest(source),
                 "tree_sha256": tree_digest(snapshot(root)), "git_status": status}
    (directory / "original-before.json").write_text(json.dumps(integrity, indent=2), encoding="utf-8")
    print("Stage 1 Fix Verification\nTarget: Juice Shop v20.2.0\nCommit: " + COMMIT, flush=True)
    print("Finding: routes/search.ts:23 / verify_sql_injection\nArtifacts: " + str(directory), flush=True)
    service = FixVerificationService()
    if args.report:
        report = FinalReport.model_validate_json(Path(args.report).read_text(encoding="utf-8"))
    else:
        report = FinalReport(finding_id=PATCH_FINDING, finding=ReportFinding(
            id=PATCH_FINDING, source="integration_fixture", rule_id="sequelize-injection.presentation",
            title="SQL interpolation in product search", file="routes/search.ts", line_start=23),
            status="inconclusive", verification=VerificationSummary(),
            code_context="\n".join(f"{i}: {line}" for i, line in enumerate(source.decode().splitlines(), 1)),
            explanation="Awaiting real capability evidence", next_step="Confirm using the original bounded capability")
        print("Confirming original finding with real Docker/Executor/Evidence...", flush=True)
        report = service.confirm_original(report=report, profile=profile, run_id=directory.name,
                                          artifact_directory=directory)
    (directory / "confirmed-report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if args.review:
        review = PatchReviewArtifact.model_validate_json(Path(args.review).read_text(encoding="utf-8"))
    else:
        review = prepare_patch_review(client=IntegrationPatchClient(source.decode()), report=report,
            repository=root, run_id=directory.name, editable_start=20, editable_end=23,
            proposal_guard=validate_sequelize_search_proposal, validation_policy=PATCH_REVIEW_POLICY)
    (directory / "patch-review.json").write_text(review.model_dump_json(indent=2), encoding="utf-8")
    print("Patch review: " + review.status + "\nRunning BEFORE/apply/AFTER...", flush=True)
    artifact = service.verify(report=report, review=review, profile=profile, artifact_directory=directory)
    after = {"commit": original_commit(root), "source_sha256": digest((root / "routes/search.ts").read_bytes()),
             "tree_sha256": tree_digest(snapshot(root)),
             "git_status": _command(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"])}
    (directory / "original-after.json").write_text(json.dumps(after, indent=2), encoding="utf-8")
    if after != integrity:
        artifact = artifact.model_copy(update={"status": "INCONCLUSIVE", "security_verified": False,
            "verdict": "inconclusive", "original_unchanged": False, "explanation": "Original commit/status/manifest changed"})
    (directory / "fix-verification.json").write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    for phase in ("before", "after"):
        print(phase.upper(), flush=True)
        for stage in artifact.stages:
            if stage.phase == phase:
                print(f"  {stage.stage}: {stage.status} ({stage.duration_ms} ms)", flush=True)
        evidence = artifact.before_evidence if phase == "before" else artifact.after_evidence
        print("  Security verification: " + (evidence.verdict.upper() if evidence else "UNAVAILABLE"), flush=True)
    print(f"PATCH applied: {artifact.applied}\nOriginal integrity: {after == integrity}\nCleanup: {artifact.cleanup_complete}", flush=True)
    print(f"FINAL: {artifact.status}\nsecurity_verified: {artifact.security_verified}\n{artifact.explanation}", flush=True)
    return 0 if artifact.security_verified else 1


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=str(ROOT / "artifacts/stage1-juice-shop"))
    parser.add_argument("--fix-image")
    parser.add_argument("--worker-image")
    parser.add_argument("--report", help="Existing confirmed FinalReport, or confirm a fresh finding")
    parser.add_argument("--review", help="Existing strict PatchReviewArtifact, or generate the registered SQL proposal")
    parser.add_argument("--output-dir", default=str(ROOT / "artifacts/stage1-e2e"))
    try:
        return run(parser.parse_args())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("Stage 1 INCONCLUSIVE: " + redact_error_message(str(exc)), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
