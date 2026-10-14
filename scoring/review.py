"""Resolve operator source reviews without reading any benchmark answers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from schemas.finding import Finding
from schemas.scoring import ScoringReview, ScoringReviewResolution, TechnicalSeverity
from scoring.service import ScoringService


def finding_review_digest(finding: Finding) -> str:
    # Service/PR/provenance can be enriched by orchestration without changing the observation.
    data = finding.model_dump(mode="json", exclude={"service", "pr_context", "provenance"})
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_reviews(path: str | Path) -> dict[str, ScoringReview]:
    source = Path(path)
    if source.stat().st_size > 1_048_576:
        raise ValueError("Scoring reviews exceed the 1 MiB input limit")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) > 1000:
        raise ValueError("Scoring reviews must be a list of at most 1000 entries")
    reviews = [ScoringReview.model_validate(item) for item in data]
    if len({item.finding_id for item in reviews}) != len(reviews):
        raise ValueError("Duplicate finding scoring review")
    return {item.finding_id: item for item in reviews}


def resolve_review(finding: Finding, root: Path, review: ScoringReview | None):
    resolution = ScoringReviewResolution()
    severity = TechnicalSeverity()
    if review is None:
        return None, frozenset(), severity, resolution
    digest = hashlib.sha256(review.model_dump_json().encode()).hexdigest()
    try:
        if review.finding_id != finding.id or review.finding_digest != finding_review_digest(finding):
            raise ValueError("Scoring review does not match the finding observation")
        ids = [ref.id for ref in review.references]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate source reference ID")
        if review.cvss is not None and review.cvss.finding_id != finding.id:
            raise ValueError("CVSS inputs belong to another finding")
        anchored = False
        root = root.resolve(strict=True)
        for ref in review.references:
            relative = PurePosixPath(ref.file)
            if (relative.is_absolute() or ".." in relative.parts or "\\" in ref.file
                    or ":" in ref.file or relative.as_posix() != ref.file):
                raise ValueError("Non-canonical source reference path")
            source = root / ref.file
            if not source.resolve(strict=True).is_relative_to(root) or source.is_symlink():
                raise ValueError("Source reference escapes the target or is a symlink")
            if source.stat().st_size > 2_097_152:
                raise ValueError("Source reference exceeds 2 MiB")
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != ref.sha256:
                raise ValueError("Reviewed source digest changed")
            lines = raw.decode("utf-8").splitlines()
            if ref.line_end < ref.line_start or ref.line_end > len(lines):
                raise ValueError("Reviewed source range is invalid")
            if (ref.file == finding.file and finding.line_start is not None
                    and ref.line_start <= (finding.line_end or finding.line_start)
                    and finding.line_start <= ref.line_end):
                anchored = True
        if not anchored:
            raise ValueError("Review must include the finding source anchor")
        by_id = {ref.id: ref for ref in review.references}
        if review.cvss is not None:
            for metric, fact in review.cvss.metrics.items():
                if any(ref not in by_id or metric not in by_id[ref].metrics
                       for ref in fact.evidence_refs):
                    raise ValueError("Metric justification lacks its explicitly reviewed source fact")
        if any(not any(impact in ref.impacts for ref in review.references)
               for impact in review.impacts):
            raise ValueError("Ordinal impact lacks an explicitly reviewed source fact")
    except (OSError, UnicodeError, ValueError):
        # Fixed diagnostic cannot leak absolute host paths or source text.
        return None, frozenset(), severity, ScoringReviewResolution(
            status="invalid", review_digest=digest,
            diagnostics=["Review rejected: finding, source digest, range or fact binding mismatch."],
        )
    if review.impacts:
        severity = TechnicalSeverity(
            level="HIGH", assessment_status="assessed", impact_facts=review.impacts,
            reasoning="Operator-reviewed source-impact rubric: " + review.rationale,
        )
    return review.cvss, frozenset(ids), severity, ScoringReviewResolution(
        status="accepted", review_digest=digest, reviewed_by=review.reviewed_by,
        references=review.references,
        diagnostics=["Source-based operator assessment; not a runtime vulnerability verdict."],
    )


def score_state(state):
    finding = state["finding"]
    profile = state.get("target_profile")
    review = state.get("scoring_review")
    root = profile.repository_path if profile is not None else None
    if review is not None and root is None:
        assessment, refs, severity, resolution = None, frozenset(), TechnicalSeverity(), (
            ScoringReviewResolution(status="invalid", diagnostics=["No trusted target root."])
        )
    else:
        assessment, refs, severity, resolution = resolve_review(finding, root, review)
    cvss, priority = ScoringService().score(
        finding, state["architecture_context"], assessment=assessment, trusted_evidence_refs=refs,
    )
    return {"cvss": cvss, "context_priority": priority,
            "technical_severity": severity, "scoring_review_resolution": resolution}
