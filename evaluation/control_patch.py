"""One reviewed upstream redirect fix; no automatic answer-to-safe conversion."""
from difflib import unified_diff
from pathlib import Path

from evaluation.control_catalog import sha
from fix_verification.review import validate_review_diff
from fix_verification.workspace import safe_file
from schemas.fix import ProposedPatch

SOURCE = "lib/insecurity.ts"
CORRECT = "data/static/codefixes/redirectChallenge_4_correct.ts"


def redirect_patch(target: Path) -> dict:
    raw = safe_file(target, SOURCE).read_bytes()
    source = raw.decode().replace("\r\n", "\n")
    correct = safe_file(target, CORRECT).read_text(encoding="utf-8").replace("\r\n", "\n")
    start = source.index("export const redirectAllowlist")
    end = source.index("// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge", start)
    window = source[start:end]
    clean = "\n".join(line.split("// vuln-code-snippet", 1)[0].rstrip() for line in window.splitlines()).strip()
    old = "allowed = allowed || url.includes(allowedUrl)"
    new = "allowed = allowed || url === allowedUrl"
    if clean.count(old) != 1 or clean.replace(old, new) != correct.strip():
        raise ValueError("Correct fix/source correspondence mismatch")
    after = source.replace(old, new)
    diff = "".join(unified_diff(source.splitlines(keepends=True), after.splitlines(keepends=True),
                                fromfile="a/" + SOURCE, tofile="b/" + SOURCE, n=3))
    line = source[:source.index(old)].count("\n") + 1
    reviewed = validate_review_diff(ProposedPatch(finding_id="A03-redirect-candidate",
        rationale="Operator-reviewed exact upstream codefix correspondence", unified_diff=diff),
        file=SOURCE, source=source, editable_start=line, editable_end=line)
    if reviewed != diff:
        raise ValueError("Noncanonical patch")
    return {"file":SOURCE, "diff":diff, "source_sha256":sha(raw), "patch_sha256":sha(diff.encode()),
            "correct_file":CORRECT, "correct_sha256":sha(correct.encode()),
            "editable_line":line}
