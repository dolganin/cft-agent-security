"""Operator-only initial A06 freeze. Never overwrites an existing scanner lock."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from evaluation.scanner_baseline import PROFILE_DIR, ROOT, command, input_sha, sha, write

PACKS = ("javascript", "typescript", "generic", "dockerfile", "yaml", "html", "json")
INPUTS = ("profile.yaml", "semgrep-rules.yaml", "rules-provenance.json", "RULES-LICENSE.txt")
CODE = ("evaluation/zap_baseline_worker.py", "evaluation/baseline_adapter.py",
        "evaluation/semgrep_baseline_worker.py",
        "evaluation/scanner_baseline.py", "schemas/baseline.py", "app/scanner_baseline.py", "security/source_paths.py")


def snapshot_rules(source, output):
    """Select security YAML by language directory, never by target/case/score."""
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("Rules output already exists; preserve prior snapshots")
    commit = command(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.strip()
    if command(["git", "-C", str(source), "status", "--porcelain"]).stdout:
        raise ValueError("Upstream rules checkout must be clean")
    rules, provenance = [], []
    for pack in PACKS:
        for file in sorted((source / pack).rglob("*.yaml")):
            relative = file.relative_to(source).as_posix()
            if ("security" not in file.relative_to(source).parts
                    or ".test." in file.name or "tests" in file.relative_to(source).parts):
                continue
            document = yaml.safe_load(file.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not document.get("rules"):
                continue
            if any(not isinstance(r, dict) or "id" not in r for r in document["rules"]):
                raise ValueError("Invalid upstream rule document: " + relative)
            ids = []
            for rule in document["rules"]:
                # Preserve upstream semantics; directory-prefix IDs avoid collisions
                # that Semgrep's per-file automatic rewrite ordinarily handles.
                rule["id"] = file.relative_to(source).with_suffix("").as_posix().replace("/", ".") + "." + rule["id"]
                ids.append(rule["id"])
                rules.append(rule)
            provenance.append({"path": relative, "sha256": sha(file), "rule_ids": ids})
    if not rules or len({r["id"] for r in rules}) != len(rules):
        raise ValueError("Empty ruleset or duplicate rule IDs")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True),
                      encoding="utf-8", newline="\n")
    write(output.parent / "rules-provenance.json", {
        "upstream": "https://github.com/semgrep/semgrep-rules", "commit": commit,
        "selection": {"language_directories": PACKS, "required_path_component": "security",
                      "target_or_expected_label_filters": False},
        "rule_count": len(rules), "files": provenance,
        "license": "https://semgrep.dev/legal/rules-license",
    })
    (output.parent / "RULES-LICENSE.txt").write_bytes((source / "LICENSE").read_bytes())
    return len(rules)


def freeze(directory=PROFILE_DIR):
    destination = directory / "scanners.lock.json"
    if destination.exists():
        raise ValueError("Existing freeze cannot be overwritten; create a new scanner version")
    paths = [directory / name for name in INPUTS] + [ROOT / name for name in CODE]
    payload = {"schema_version": "baseline.scanners.lock.a06.v1",
               "input_encoding": "utf8_lf",
               "inputs": {p.relative_to(ROOT).as_posix(): input_sha(p) for p in paths}}
    write(destination, payload)
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["rules", "freeze"])
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if args.command == "rules":
        if args.source is None:
            parser.error("rules requires --source (clean upstream Git checkout)")
        print(snapshot_rules(args.source, PROFILE_DIR / "semgrep-rules.yaml"))
    else:
        print(json.dumps(freeze(), indent=2))


if __name__ == "__main__":
    main()
