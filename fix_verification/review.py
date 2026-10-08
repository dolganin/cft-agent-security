"""Read-only patch preparation. No subprocess, target writes, or test execution."""
from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fix_verification.proposal import PatchProposalService, StructuredPatchClient
from schemas.fix import PatchReviewArtifact, ProposedPatch
from schemas.report import FinalReport
from security.error_redaction import redact_error_message
from tools.repository_source import _safe_line

_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?")
_CREDENTIAL = re.compile(r"sk-[\w-]{16,}|-----BEGIN .*PRIVATE KEY|<redacted>")


def validate_sequelize_search_proposal(diff: str) -> None:
    """Conservative operator-owned review rule for the supported Sequelize shape.

    Sequelize v6 uses :name with replacements, $name with bind. This syntactic
    check is NOT runtime proof, and deliberately rejects broader refactoring.
    Reference: https://sequelize.org/docs/v6/core-concepts/raw-queries/
    """
    removed = [line[1:] for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    if len(removed) != 1 or "models.sequelize.query(" not in removed[0]:
        raise ValueError("Only the vulnerable search query may change in this review policy")
    match = re.fullmatch(
        r"\s*models\.sequelize\.query\((?P<quote>['\"`])(?P<sql>[^\n]+?)(?P=quote),\s*"
        r"\{\s*(?P<option>replacements|bind)\s*:\s*\{\s*(?P<key>[a-zA-Z_]\w*)\s*:\s*"
        r"`%\$\{criteria\}%`\s*\}\s*\}\s*\)\s*",
        "\n".join(added),
    )
    if match is None:
        raise ValueError("Unsupported query rewrite; preserve behavior using the documented parameter API")
    placeholder = (":" if match["option"] == "replacements" else "$") + match["key"]
    expected = (
        f"SELECT * FROM Products WHERE ((name LIKE {placeholder} OR description LIKE {placeholder}) "
        "AND deletedAt IS NULL) ORDER BY name"
    )
    if match["sql"] != expected:
        raise ValueError("SQL text/options mismatch or changed query behavior")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_review_diff(
    proposal: ProposedPatch, *, file: str, source: str,
    editable_start: int, editable_end: int,
) -> str:
    """Check exact context/counts and build a canonical diff without writing it.

    Benchmark annotation comments are removed only from model context, not from
    unchanged source. Validation here establishes scope and applicability only.
    It does not establish that the proposed code fixes the security condition.
    """
    path = PurePosixPath(file)
    if path.is_absolute() or ".." in path.parts or "\\" in file:
        raise ValueError("Unsafe source path")
    diff = proposal.unified_diff
    if len(diff.encode()) > 16_384 or "\r" in diff.replace("\r\n", "") or _CREDENTIAL.search(diff):
        raise ValueError("Oversized diff, invalid CR line endings or credential/redaction content")
    lines = diff.splitlines()
    if lines and lines[0] == f"diff --git a/{file} b/{file}":
        lines.pop(0)
    if lines[:2] != [f"--- a/{file}", f"+++ b/{file}"]:
        raise ValueError("Only the original finding file may be modified")
    original = source.splitlines(keepends=True)
    if not original or any(not line.endswith("\n") for line in original):
        raise ValueError("Only newline-terminated UTF-8 source is supported")
    newline = "\r\n" if all(line.endswith("\r\n") for line in original) else "\n"
    if newline == "\n" and any(line.endswith("\r\n") for line in original):
        raise ValueError("Mixed source line endings are not supported")
    clean = [_safe_line(line.rstrip("\r\n")) for line in original]
    output: list[str] = []
    cursor = 0
    index = 2
    changed = 0
    hunks = 0
    while index < len(lines):
        match = _HUNK.fullmatch(lines[index])
        if not match:
            raise ValueError("Unsupported diff header or metadata")
        old_start, old_count, new_start, new_count = (
            int(match[1]), int(match[2] or "1"), int(match[3]), int(match[4] or "1")
        )
        if old_start < 1 or old_count < 1 or old_start - 1 < cursor or old_start > len(original):
            raise ValueError("Invalid or overlapping source hunk")
        output.extend(original[cursor:old_start - 1])
        cursor = old_start - 1
        if new_start != len(output) + 1:
            raise ValueError("Invalid output hunk offset")
        removed = added = 0
        index += 1
        hunks += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if not line or line[0] not in " +-":
                raise ValueError("Unsupported diff content")
            prefix, text = line[0], line[1:]
            if prefix == "+" and text != text.rstrip():
                raise ValueError("Added source lines must not introduce trailing whitespace")
            if len(text) > 2_000:
                raise ValueError("Diff line exceeds the bounded source width")
            if prefix in " -":
                if cursor >= len(clean) or text not in {
                    clean[cursor], original[cursor].rstrip("\r\n"),
                }:
                    raise ValueError("Diff context does not match the source snapshot")
                if prefix == "-" and not editable_start <= cursor + 1 <= editable_end:
                    raise ValueError("Removal is outside the operator-selected source window")
                if prefix == " ":
                    output.append(original[cursor])
                    added += 1
                else:
                    changed += 1
                cursor += 1
                removed += 1
            else:
                if not editable_start <= cursor + 1 <= editable_end + 1:
                    raise ValueError("Addition is outside the operator-selected source window")
                output.append(text + newline)
                added += 1
                changed += 1
            index += 1
        if (removed, added) != (old_count, new_count):
            raise ValueError("Hunk line counts do not match the diff")
    if not hunks or not 1 <= changed <= 64:
        raise ValueError("A small nonempty patch is required")
    output.extend(original[cursor:])
    canonical = "".join(difflib.unified_diff(
        original, output, fromfile=f"a/{file}", tofile=f"b/{file}", n=3,
    ))
    if not canonical or _CREDENTIAL.search(canonical) or any(
        "<redacted>" in _safe_line(line) for line in canonical.splitlines()
    ):
        raise ValueError("Patch is empty or contains credential/redaction content")
    return canonical


def prepare_patch_review(
    *, client: StructuredPatchClient, report: FinalReport, repository: Path,
    run_id: str, editable_start: int, editable_end: int,
    proposal_guard: Callable[[str], None] | None = None,
    validation_policy: str = "single_file_scope_v1",
    trusted_guidance: str = "",
) -> PatchReviewArtifact:
    if report.status != "confirmed" or not report.evidence:
        raise ValueError("Only evidence-backed confirmed findings are eligible")
    file = report.finding.file
    path = PurePosixPath(file)
    if path.is_absolute() or ".." in path.parts or "\\" in file:
        raise ValueError("Unsafe source path")
    root = repository.resolve(strict=True)
    target = root / file
    resolved = target.resolve(strict=True)
    if not resolved.is_relative_to(root) or any(
        (root / PurePosixPath(*path.parts[:index])).is_symlink()
        for index in range(1, len(path.parts) + 1)
    ):
        raise ValueError("Linked source paths are not accepted")
    with resolved.open("rb") as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072 or b"\0" in raw:
        raise ValueError("Source file exceeds the text budget")
    source = raw.decode("utf-8")
    clean = [_safe_line(line) for line in source.splitlines()]
    if not 1 <= editable_start <= editable_end <= len(clean):
        raise ValueError("Invalid operator source window")
    # The editable condition must still match the completed report. Unrelated
    # bytes are bound to the current file digest, not asserted to be historical.
    previous = {}
    for line in report.code_context.splitlines():
        number, separator, content = line.partition(": ")
        if separator and number.strip().isdigit():
            previous[int(number)] = _safe_line(content)
    if any(previous.get(number) != clean[number - 1]
           for number in range(editable_start, editable_end + 1)):
        raise ValueError("Finding source changed since the completed report")
    start, end = max(1, editable_start - 2), min(len(clean), editable_end + 2)
    window = "\n".join(f"{number}: {clean[number - 1]}" for number in range(start, end + 1))
    if "<redacted>" in window:
        raise ValueError("Masked source cannot be safely reconstructed for a patch")
    context = (
        f"Operator scope: only {file}, editable original lines {editable_start}-{editable_end}.\n"
        "Return a strict unified diff with --- a/path, +++ b/path and exact hunk counts.\n"
        "Preserve endpoint behavior. Prefer bound SQL parameters, do not remove functionality.\n"
        "Use only the supplied window; numbered prefixes are not source text.\n"
        "Explain the defensive change in Russian as a proposal, never claim runtime success.\n"
        "The patch will NOT be executed.\n" + trusted_guidance + "\n" + window
    )
    scoped = report.model_copy(update={"code_context": context})
    # Only structured observed facts are sent, never host artifact paths or SDK state.
    scoped = scoped.model_copy(update={"evidence": [item.model_copy(update={
        "artifact_refs": [], "artifacts": [],
    }) for item in report.evidence]})
    proposal = PatchProposalService(client).propose(scoped)
    if resolved.read_bytes() != raw:
        raise ValueError("Source changed while the proposal was generated")
    status = "ready_for_review"
    detail = "Файл, окно изменений, контекст и счетчики diff проверены. Код не выполнялся."
    try:
        canonical = validate_review_diff(
            proposal, file=file, source=source,
            editable_start=editable_start, editable_end=editable_end,
        )
        if proposal_guard is not None:
            proposal_guard(canonical)
        proposal = proposal.model_copy(update={"unified_diff": canonical})
    except ValueError as exc:
        status = "rejected"
        detail = str(exc)
        # Rejected model text can contain secrets or external paths. Do not
        # persist or expose its diff/rationale; keep only the safe explanation.
        proposal = ProposedPatch(finding_id=report.finding_id, rationale="Предложение отклонено.", unified_diff="")
    proposal = proposal.model_copy(update={"rationale": redact_error_message(proposal.rationale, max_length=2_000)})
    route = getattr(client, "last_selected_route", None)
    return PatchReviewArtifact(
        id=f"patch-{uuid4().hex}", run_id=run_id, finding_id=report.finding_id,
        file=file, status=status, source_sha256=_digest(raw),
        proposal_sha256=_digest(proposal.model_dump_json().encode()),
        model=route.label if route else None, generated_at=datetime.now(UTC),
        proposal=proposal, validation_detail=detail,
        validation_policy=validation_policy,
        editable_start=editable_start, editable_end=editable_end,
        limitations=[
            "Это предложение для ревью, не доказанное исправление.",
            "Патч не применялся; сборка, тесты и повтор security-проверки не выполнялись.",
            "Исходный отчет и решение CI не изменены.",
        ],
    )
