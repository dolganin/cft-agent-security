"""Only operator-authored categories reach the next model request."""
from schemas.repair_loop import RepairFeedback
from tools.repository_source import _safe_line

MESSAGES = {
    "invalid_structured_output": (
        "The provider response did not match the required JSON schema. "
        "Return only finding_id, rationale and unified_diff with string values, within the supplied limits."
    ),
    "invalid_diff_format_or_window": (
        "The diff did not match the supplied source window or unified-diff format. "
        "Use exact original lines, headers, offsets and hunk counts; edit only the permitted window."
    ),
    "finding_id_mismatch": "Return exactly the supplied finding_id with the proposed patch.",
    "NOT_FIXED": (
        "Independent verification still confirmed the original vulnerability after the patch. "
        "Revise the permitted change while preserving the required legitimate behavior."
    ),
    "REGRESSION": (
        "The patched application failed required functional checks. "
        "Preserve the supplied legitimate behavior and revise only the permitted source window."
    ),
    "AFTER_BUILD_FAILED": (
        "BEFORE reproduced the vulnerability; AFTER failed the required build stage. "
        "The failure is not proof that the patch caused it. Check the previous proposal's syntax "
        "and compatibility within the supplied source window; preserve legitimate behavior."
    ),
    "AFTER_TESTS_FAILED": (
        "BEFORE reproduced the vulnerability; AFTER failed the required native test stage. "
        "No security fix was established and the failure's cause is not attributed to the patch. "
        "Reconsider the previous proposal against the supplied legitimate behavior; do not change tests."
    ),
}


def proposal_view(review) -> dict:
    """Keep the prior edit, projecting source lines exactly like C02 context."""
    from fix_verification.workspace import digest

    patch = review.proposal.unified_diff
    lines = [line[0] + _safe_line(line[1:])
             if line[:1] in {" ", "+", "-"} and not line.startswith(("--- ", "+++ "))
             else line for line in patch.splitlines()]
    return {"patch_sha256": digest(patch.encode()), "unified_diff": "\n".join(lines) + "\n"}


def feedback_for(attempt: int, stage: str, code: str, patch_sha256=None) -> RepairFeedback | None:
    if code not in MESSAGES:
        return None
    return RepairFeedback(attempt=attempt, stage=stage, code=code,
                          summary=MESSAGES[code], previous_patch_sha256=patch_sha256)


def validate_feedback(value: RepairFeedback) -> dict:
    """Do not accept model/verifier prose, private test outputs or arbitrary diagnostics."""
    expected = feedback_for(value.attempt, value.stage, value.code, value.previous_patch_sha256)
    if expected != value or (value.stage == "generation") != (value.code not in {
            "NOT_FIXED", "REGRESSION", "AFTER_BUILD_FAILED", "AFTER_TESTS_FAILED"}):
        raise ValueError("Untrusted repair feedback")
    return value.model_dump(mode="json")
