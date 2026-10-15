"""C01 scope sealing, baseline replay and fail-closed patch boundaries.

No execution approval, target execution or patch application is performed here.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from evaluation.offline_rescore import observations_from_artifacts
from fix_verification.review import validate_review_diff
from fix_verification.workspace import digest, safe_file
from schemas.fix import ProposedPatch
from schemas.fix_scope import FixEligibility, FixFamilySpec, FixScopeReport

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "contracts/c01"
SOURCE_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
BASELINE = ROOT / "artifacts/handoffs/b09-single-2026-10-15.zip"


def load_scope() -> tuple[list[FixFamilySpec], dict]:
    lock_raw = (SCOPE / "lock.json").read_bytes()
    lock = json.loads(lock_raw)
    for name, expected in lock["files"].items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Unsafe evaluator lock path")
        raw = safe_file(ROOT, name).read_bytes()
        # Git may check text out as CRLF on Windows; archive bytes stay exact.
        if path.suffix in {".py", ".json", ".cjs", ".patch"}:
            raw = raw.replace(b"\r\n", b"\n")
        if digest(raw) != expected:
            raise ValueError("Protected evaluator/baseline digest mismatch: " + name)
    specs = [FixFamilySpec.model_validate(item) for item in
             json.loads((SCOPE / "families.json").read_text(encoding="utf-8"))]
    if len(specs) not in {2, 3} or len({item.id for item in specs}) != len(specs):
        raise ValueError("C01 requires two or three distinct operator families")
    return specs, lock


def validate_candidate(*, family_id: str, proposal: ProposedPatch,
                       source_root: Path, source_sha256: str) -> str:
    """Only an existing exact allowlisted source file; evaluator stays outside snapshot.

    This is a scope/applicability check, never a security verdict. C02/C03 must
    call it before application and recheck the lock after verification.
    """
    specs, _ = load_scope()
    spec = next((s for s in specs if s.id == family_id), None)
    if spec is None:
        raise ValueError("Family is ineligible for C01")
    headers = re.findall(r"^--- a/(.+)$", proposal.unified_diff, re.MULTILINE)
    if len(headers) != 1 or headers[0] not in spec.allowed_files:
        raise ValueError("Patch may change only one explicitly allowed application file")
    file = headers[0]
    raw = safe_file(source_root, file).read_bytes()
    if digest(raw) != source_sha256:
        raise ValueError("Candidate source snapshot mismatch")
    source = raw.decode("utf-8")
    return validate_review_diff(proposal, file=file, source=source,
                               editable_start=1, editable_end=len(source.splitlines()))


def _verified_archive(archive: Path, destination: Path):
    """Validate every archived byte before bounded extraction; never trust ZIP paths."""
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("Duplicate or excessive archive members")
        if sum(item.file_size for item in zipped.infolist()) > 128 * 1024 * 1024:
            raise ValueError("Baseline archive exceeds budget")
        manifest = json.loads(zipped.read("MANIFEST-SHA256.json"))
        if set(names) != {*manifest, "MANIFEST-SHA256.json"}:
            raise ValueError("Baseline membership mismatch")
        for name, expected in manifest.items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
                raise ValueError("Unsafe baseline path")
            raw = zipped.read(name)
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("Baseline member digest mismatch")
            output = destination / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(raw)


def assess_scope() -> FixScopeReport:
    specs, lock = load_scope()
    entries = []
    with tempfile.TemporaryDirectory(prefix="cft-c01-replay-") as temp:
        root = Path(temp)
        _verified_archive(BASELINE, root)
        baseline = root / "b09-single-2026-10-15-final"
        observations = observations_from_artifacts(baseline / "pipeline")
        review = json.loads((baseline / "evaluation/confirmed-review.json").read_text())
        for spec in specs:
            reviewed_ids = {row["finding_id"] for row in review
                            if row["capability"] == spec.capability
                            and any(match["case_id"] in spec.case_ids
                                    for match in row["matches"])}
            selected = [o for o in observations if o.id in reviewed_ids
                        and o.capability == spec.capability and o.http_endpoint == spec.endpoint
                        and o.source_file in spec.allowed_files
                        and o.verification == "confirmed" and o.evidence_backed]
            entries.append(FixEligibility(
                family_id=spec.id, status="eligible" if selected else "failed",
                reason="B09 persisted execution/audit and approved trace replay matched"
                if selected else "Missing or invalid original evidence; do not attempt repair",
                finding_ids=[o.id for o in selected],
                evidence_refs=sorted({r for o in selected for r in o.evidence}),
            ))
    for family, reason in lock["excluded_families"].items():
        entries.append(FixEligibility(family_id=family, status="ineligible", reason=reason))
    return FixScopeReport(source_commit=SOURCE_COMMIT,
        baseline_archive_sha256=digest(BASELINE.read_bytes()),
        evaluator_lock_sha256=digest((SCOPE / "lock.json").read_bytes()), entries=entries,
        eligible=sum(e.status == "eligible" for e in entries),
        failed=sum(e.status == "failed" for e in entries),
        ineligible=sum(e.status == "ineligible" for e in entries))
