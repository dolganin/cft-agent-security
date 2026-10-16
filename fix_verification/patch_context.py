"""Operator selection, bounded AST source views and archived confirmed inputs."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import tree_sitter_typescript
from tree_sitter import Language, Parser

from fix_verification.scope import BASELINE, _verified_archive, assess_scope, load_scope
from fix_verification.workspace import digest, safe_file
from schemas.report import FinalReport
from security.error_redaction import redact_observation
from tools.repository_source import _safe_line

FILES = {"sql-search": "routes/search.ts", "redirect-allowlist": "lib/insecurity.ts"}


def original_input(family: str):
    specs, _ = load_scope()
    spec = next((item for item in specs if item.id == family), None)
    if spec is None or family not in FILES:
        raise ValueError("unselected_family")
    eligibility = assess_scope()
    eligible = next(item for item in eligibility.entries if item.family_id == family)
    if eligible.status != "eligible":
        raise ValueError("missing_original_evidence")
    with tempfile.TemporaryDirectory(prefix="cft-c02-baseline-") as temporary:
        root = Path(temporary)
        _verified_archive(BASELINE, root)
        baseline = root / "b09-single-2026-10-15-final"
        reports = []
        for path in (baseline / "pipeline/reports").glob("*.json"):
            raw = path.read_bytes()
            report = FinalReport.model_validate_json(raw)
            if report.finding_id in eligible.finding_ids and report.finding.file == FILES[family]:
                reports.append((report, digest(raw)))
        if len(reports) != 1:
            raise ValueError("ambiguous_original_report")
        run = json.loads((baseline / "run-result.json").read_text())
        if not run["source_unchanged"]:
            raise ValueError("baseline_source_changed")
    return spec, reports[0][0], reports[0][1], run["target_snapshot_after"]


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def source_view(repository: Path, family: str):
    file = FILES[family]
    raw = safe_file(repository, file).read_bytes()
    if len(raw) > 131072 or b"\0" in raw:
        raise ValueError("source_budget")
    tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(raw)
    if tree.root_node.has_error:
        raise ValueError("invalid_source_ast")
    if family == "sql-search":
        selected = [node for node in walk(tree.root_node) if node.type == "call_expression"
            and node.child_by_field_name("function") is not None
            and node.child_by_field_name("function").text == b"models.sequelize.query"
            and b"criteria" in node.text]
    else:
        selected = [node for node in walk(tree.root_node) if node.type == "variable_declarator"
            and node.child_by_field_name("name") is not None
            and node.child_by_field_name("name").text == b"isRedirectAllowed"]
    if len(selected) != 1:
        raise ValueError("ambiguous_source_window")
    node = selected[0]
    start, end = node.start_point.row + 1, node.end_point.row + 1
    lines = raw.decode().splitlines()
    context_start, context_end = max(1, start-2), min(len(lines), end+2)
    context = "\n".join(f"{i}: {_safe_line(lines[i-1])}" for i in range(context_start, context_end+1))
    if len(context.encode()) > 12000 or len(context.splitlines()) > 80:
        raise ValueError("context_budget")
    # No masked literals can be reconstructed into a patch. Never expose the
    # rest of insecurity.ts (it contains the target's seeded private key).
    if "<redacted" in context or redact_observation(context) != context:
        raise ValueError("secret_in_source_window")
    return file, raw, start, end, context


def evidence_view(report: FinalReport) -> list[dict]:
    result = []
    for item in report.evidence[:4]:
        if item.verdict != "confirmed" or item.source != "runtime":
            continue
        facts = item.observation.facts
        nested = facts.get("facts", {})
        public = {"evidence_id": item.id, "verdict": item.verdict,
            "source": item.source, "reliability": item.reliability,
            "summary": redact_observation(item.summary[:1000]),
            "capability": item.action.tool, "action_id": item.action_id}
        for key in ("control_repeated", "probe_repeated", "response_values_redacted"):
            if type(nested.get(key)) is bool:
                public[key] = nested[key]
        if type(nested.get("requests")) is int:
            public["requests"] = nested["requests"]
        if isinstance(facts.get("trials"), list):
            public["independent_trials"] = len(facts["trials"])
        result.append(public)
    if not result:
        raise ValueError("missing_runtime_evidence")
    return result
