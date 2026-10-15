"""Independent, source-only review of bounded scanner candidates."""
import json
from hashlib import sha256
from pathlib import Path

from evidence.research_source_reviewer import review
from security.source_paths import normalize_source_path


def review_scanner_source_conditions(*, root, findings, output, source_sha256=None):
    """Verify explicit weak-digest calls without changing runtime finding verdicts."""
    root, output = Path(root).resolve(strict=True), Path(output)
    if output.exists():
        raise FileExistsError("Source-condition review requires a fresh output directory")
    output.mkdir(parents=True)
    reports, seen = [], set()
    for finding in findings:
        provenance = finding.provenance
        if (provenance is None or provenance.family != "weak-cryptography"
                or provenance.anchor_status != "source_bound" or finding.line_start is None):
            continue
        identity = (finding.file, finding.line_start, finding.line_end, provenance.file_sha256)
        if identity in seen:
            continue
        seen.add(identity)
        row = {"finding_id": finding.id, "rule_id": finding.rule_id, "scope": "source_condition",
            "runtime_verdict_changed": False, "review": {"status": "review_pending"}}
        try:
            relative = normalize_source_path(finding.file, root)
            path = root / relative
            raw = path.read_bytes()
            end = finding.line_end or finding.line_start
            if (len(raw) > 1048576 or sha256(raw).hexdigest() != provenance.file_sha256
                    or not 1 <= finding.line_start <= end or end - finding.line_start >= 160):
                raise ValueError("Source range or digest is not bound")
            result = review(raw, relative, finding.line_start, end)
            if path.read_bytes() != raw:
                raise ValueError("Source changed during review")
            row.update({"file": relative, "line_start": finding.line_start,
                        "line_end": end, "review": result})
        except (ValueError, OSError):
            row["reason"] = "Candidate source binding unavailable; no source proof"
        reports.append(row)
    result = {"schema": "cft.research.source-condition-reviews.v1", "scope": "source_condition_only",
        "runtime_verdicts_changed": False, "reviewed_findings": len(reports), "reviews": reports}
    if (source_sha256 and {"models/user.ts", "lib/insecurity.ts"} <= source_sha256.keys()
            and any(row.get("file") == "lib/insecurity.ts" for row in reports)):
        from evidence.password_storage_review import review_password_storage
        result["password_storage_review"] = review_password_storage(root=root,
            model_file="models/user.ts", helper_file="lib/insecurity.ts", source_sha256=source_sha256)
    (output / "reviews.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result
