"""Qualify C01 independent source tests on original and operator reference variants.

This never runs target code on the host, never publishes FIXED and does not
implement C02 model generation or C03 full runtime patch verification.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from fix_verification.scope import SOURCE_COMMIT, assess_scope, load_scope, validate_candidate
from fix_verification.scope_source import expressions
from fix_verification.workspace import apply_patch, digest, original_commit, safe_file
from schemas.fix import ProposedPatch

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"


def run(target: Path, output: Path) -> dict:
    load_scope()
    if original_commit(target) != SOURCE_COMMIT:
        raise ValueError("Expected pinned Juice Shop source commit")
    clean = subprocess.run(["git", "-C", str(target), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True, check=True, timeout=15)
    if clean.stdout.strip():
        raise ValueError("Original target must be clean")
    output.mkdir(parents=True, exist_ok=False)
    original = expressions(target)
    baseline = {name: digest(safe_file(target, name).read_bytes())
                for name in ("routes/search.ts", "lib/insecurity.ts", "routes/redirect.ts")}
    eligibility = assess_scope()
    if eligibility.failed or eligibility.eligible != 2:
        raise ValueError("Original evidence not eligible")
    results = []
    # Actual operator reference diffs must pass the same scope check and apply
    # to disposable data snapshots before AST extraction. No host target execution.
    with tempfile.TemporaryDirectory(prefix="cft-c01-reference-") as temporary:
        reference_root = Path(temporary)
        for file in ("routes/search.ts", "lib/insecurity.ts"):
            copied = reference_root / file
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(safe_file(target, file).read_bytes())
        for family, file in (("sql-search", "routes/search.ts"),
                             ("redirect-allowlist", "lib/insecurity.ts")):
            patch = ProposedPatch(finding_id=family, rationale="Operator evaluator qualification only",
                unified_diff=(ROOT / f"contracts/c01/reference/{family}.patch").read_text(encoding="utf-8"))
            canonical = validate_candidate(family_id=family, proposal=patch,
                source_root=reference_root, source_sha256=digest(safe_file(reference_root, file).read_bytes()))
            apply_patch(reference_root, canonical, file)
        reference = expressions(reference_root)
    safe_sql, safe_redirect = reference["sql"], reference["redirect"]
    variants = {
        "original": original,
        "reference-parameterized-exact": {**original, "sql": safe_sql, "redirect": safe_redirect},
        "deny-all": {**original, "sql": "models.sequelize.query('SELECT * FROM Products WHERE 0')",
                     "redirect": safe_redirect.split("const isRedirectAllowed =", 1)[0]
                         + "const isRedirectAllowed = url => false;"},
        "recorded-probe-only": {**original,
            "sql": "if(criteria.includes('1=1')) criteria='no-such-product';\n" + original["sql"],
            "redirect": original["redirect"]},
    }
    # Use a syntactically valid probe-only redirect wrapper, preserving all other behavior.
    variants["recorded-probe-only"]["redirect"] = original["redirect"].replace(
        "const isRedirectAllowed =", "const originalAllowed =") + (
        "\nconst isRedirectAllowed = url => url === "
        "'https://unapproved.invalid/?next=https://github.com/juice-shop/juice-shop'"
        " ? false : originalAllowed(url);")
    cleanup = True
    for variant, value in variants.items():
        name = "cft-c01-" + uuid4().hex[:16]
        with tempfile.TemporaryDirectory(prefix="cft-c01-input-") as temporary:
            inputs = Path(temporary)
            (inputs / "expressions.json").write_text(json.dumps(value), encoding="utf-8")
            command = ["docker", "run", "--pull", "never", "--name", name,
                "--network", "none", "--read-only", "--user", "65532:65532",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--cpus", "1", "--memory", "256m", "--pids-limit", "32",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "--mount", f"type=bind,source={inputs},target=/input,readonly",
                "--mount", f"type=bind,source={ROOT / 'contracts/c01/evaluator.cjs'},target=/evaluator.cjs,readonly",
                "--entrypoint", "/nodejs/bin/node", IMAGE, "/evaluator.cjs"]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                public = json.loads(result.stdout)
                public.update(variant=variant, exit_code=result.returncode)
                results.append(public)
            finally:
                removed = subprocess.run(["docker", "rm", "-f", "-v", name],
                    capture_output=True, text=True, timeout=15, check=False)
                cleanup &= removed.returncode == 0 or "No such container" in removed.stderr
    by_name = {row["variant"]: row for row in results}

    def failures(name):
        return {t["id"] for t in by_name[name]["tests"] if t["status"] == "failed"}

    qualified = (
        not failures("reference-parameterized-exact")
        and by_name["reference-parameterized-exact"]["exit_code"] == 0
        and {"sql-security-boolean-original", "redirect-security-query-original"}
            <= failures("original")
        and {"sql-functional-name-description-order", "redirect-functional-original-allowlist"}
            <= failures("deny-all")
        and {"sql-security-boolean-independent", "redirect-security-fragment-independent"}
            <= failures("recorded-probe-only")
        and all(len(row["tests"]) == 13 and not row.get("error") for row in results)
    )
    clean_after = subprocess.run(
        ["git", "-C", str(target), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, check=True, timeout=15)
    unchanged = (not clean_after.stdout.strip() and original_commit(target) == SOURCE_COMMIT
        and all(digest(safe_file(target, name).read_bytes()) == sha for name, sha in baseline.items())
        and expressions(target) == original)
    load_scope()
    report = {"schema_version": "cft.c01-qualification.v1", "source_commit": SOURCE_COMMIT,
        "image": IMAGE, "source_sha256": baseline, "eligibility": eligibility.model_dump(mode="json"),
        "variants": results, "qualified": qualified, "original_unchanged": unchanged,
        "cleanup_complete": cleanup, "security_verified": False,
        "scope": "Independent source-level evaluator qualification; C03 runtime verification still required"}
    (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not (qualified and unchanged and cleanup):
        raise RuntimeError("C01 evaluator qualification failed; retained explicit result")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination.exists():
        raise FileExistsError("Choose a fresh qualification directory")
    try:
        report = run(args.target.resolve(), destination)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "failed.json").write_text(json.dumps({
            "status": "failed", "error_type": type(error).__name__,
            "qualified": False, "security_verified": False,
        }, indent=2) + "\n", encoding="utf-8")
        raise
    print(json.dumps({k: report[k] for k in ("qualified", "original_unchanged", "cleanup_complete")}))


if __name__ == "__main__":
    main()
