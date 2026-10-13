"""Conservative, read-only operator map resolution; no inferred execution scope.

Selectors are token anchors, not a general JavaScript call-graph parser. Unsupported
or duplicate selectors fail closed. Caller/helper edges are declared by the operator.
"""
import json
from hashlib import sha256
from pathlib import Path

import tree_sitter_typescript
from tree_sitter import Language, Parser

from sast.identity import rule_family
from schemas.finding import Finding
from schemas.verification_binding import BindingResolution, VerificationBinding
from security.source_paths import normalize_source_path

_TS = Language(tree_sitter_typescript.language_typescript())
_TSX = Language(tree_sitter_typescript.language_tsx())


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def syntax(raw, file="", strict=False):
    tree = Parser(_TSX if file.endswith((".tsx", ".jsx")) else _TS).parse(raw)
    if strict and tree.root_node.has_error:
        raise ValueError("Unsupported or malformed TypeScript/JavaScript source: " + file)
    leaves, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "comment" or node.is_missing:
            continue
        if not node.children or node.type in {"string", "template_string", "regex"}:
            leaves.append((raw[node.start_byte:node.end_byte].decode("utf-8"), node))
        else:
            stack.extend(reversed(node.children))
    return tree, leaves


def tokens(text, file=""):
    _, leaves = syntax(text.encode("utf-8"), file)
    return [(text, node.start_point.row + 1) for text, node in leaves]


def selector_span(selector, raw):
    tree, leaves = syntax(raw, selector.file, strict=True)
    source = [(text, node.start_point.row + 1) for text, node in leaves]
    needle = [t for t, _ in tokens(selector.anchor, selector.file)]
    if not needle:
        raise ValueError("Empty token selector")
    values = [t for t, _ in source]
    matches = [i for i in range(len(values) - len(needle) + 1)
               if values[i:i + len(needle)] == needle]
    if len(matches) != 1:
        raise ValueError("Selector must match exactly once: " + selector.file)
    start = matches[0]
    end = start + len(needle) - 1
    if selector.extent == "function":
        # Resolve the actual AST function body, not regex/braces in string literals.
        if needle[-1] != "{":
            raise ValueError("Function selector needs its opening body brace")
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            body = node.child_by_field_name("body")
            if (node.type in {"function_declaration", "function_expression", "arrow_function",
                              "generator_function_declaration", "generator_function"}
                    and body and body.start_byte == leaves[end][1].start_byte):
                return source[start][1], body.end_point.row + 1
            stack.extend(node.children)
        raise ValueError("Selector is not an AST function header")
    return source[start][1], leaves[end][1].end_point.row + 1


def source_snapshot(profile):
    if profile.repository_path is None:
        raise ValueError("Verification requires a source checkout")
    root = Path(profile.repository_path).resolve(strict=True)
    names = {s.file for r in profile.verification_routes for s in [r.registration, *r.sources]}
    if len(names) > 256:
        raise ValueError("Verification source inventory limit exceeded")
    raw, total = {}, 0
    for name in sorted(names):
        path = root / name
        resolved = path.resolve(strict=True)
        if (not resolved.is_relative_to(root) or resolved.relative_to(root).as_posix() != name
                or path.is_symlink()):
            raise ValueError("Noncanonical verification source path")
        with path.open("rb") as stream:
            data = stream.read(1_048_577)
        if len(data) > 1_048_576 or b"\0" in data:
            raise ValueError("Unsupported verification source file")
        total += len(data)
        if total > 32 * 1_048_576:
            raise ValueError("Verification source byte budget exceeded")
        data.decode("utf-8")
        raw[name] = data
    hashes = {name: sha256(data).hexdigest() for name, data in raw.items()}
    return raw, hashes


def resolve_binding(profile, finding):
    """Line is a hint inside a proven snapshot; it never chooses a trusted route ID."""
    try:
        file = normalize_source_path(finding.file, profile.repository_path)
        family = rule_family(finding.rule_id)
        routes = [r for r in profile.verification_routes
                  if r.family == family and any(s.file == file for s in r.sources)]
        if not routes:
            return BindingResolution(status="inconclusive", reason="No operator route for source/family")
        raw, hashes = source_snapshot(profile)
        lines = raw[file].splitlines()
        start, end = finding.line_start, finding.line_end or finding.line_start
        if not start or not end or not 1 <= start <= end or end - start >= 160:
            raise ValueError("Missing or unsupported finding source range")
        provenance = finding.provenance
        if provenance and provenance.file_sha256 and provenance.file_sha256 != hashes[file]:
            # Relocate only an exact unique previously read source anchor. Never
            # retarget a stale range to unrelated code occupying the old line.
            if not provenance.anchor_sha256:
                raise ValueError("Changed source has no relocatable anchor")
            width = end - start + 1
            positions = [i for i in range(len(lines) - width + 1)
                         if sha256(b"\n".join(lines[i:i + width])).hexdigest()
                         == provenance.anchor_sha256]
            if len(positions) != 1:
                raise ValueError("Changed source anchor missing or ambiguous; scan again")
            start, end = positions[0] + 1, positions[0] + width
        if end > len(lines):
            raise ValueError("Finding source range outside snapshot")
        anchor = sha256(b"\n".join(lines[start - 1:end])).hexdigest()
        if provenance and provenance.anchor_sha256 and anchor != provenance.anchor_sha256:
            raise ValueError("Finding anchor does not match snapshot")
        matched = []
        for route in routes:
            selector_span(route.registration, raw[route.registration.file])
            registration = [token for token, _ in tokens(route.registration.anchor)]
            if (not any(token in {repr(route.endpoint), json.dumps(route.endpoint)}
                        for token in registration)
                    or not any(registration[i:i + 2] in [[".", route.method.lower()], [".", "use"]]
                               for i in range(len(registration) - 1))):
                raise ValueError("Registration anchor does not declare the trusted method/path")
            spans = [(s.file, *selector_span(s, raw[s.file])) for s in route.sources]
            if any(name == file and lo <= start <= end <= hi for name, lo, hi in spans):
                matched.append(route)
        if len(matched) != 1:
            return BindingResolution(status="inconclusive", reason="Missing or ambiguous operator route",
                                     candidates=sorted(r.id for r in matched))
        route = matched[0]
        service = profile.services.get(route.service)
        if service is None or route.endpoint not in service.runtime_endpoints:
            raise ValueError("Operator route endpoint is no longer allowed")
        # Explicit operator helper edges may cross source-directory ownership.
        # They do not create a service or enlarge its endpoint allowlist.
        mapping = [r.model_dump(mode="json") for r in profile.verification_routes]
        binding = VerificationBinding(
            route_id=route.id, handler_id=route.handler_id, target=profile.id,
            finding_id=finding.id, family=family, source_file=file,
            line_start=start, line_end=end, anchor_sha256=anchor,
            source_snapshot=digest(hashes), source_files=hashes, map_sha256=digest(mapping),
            service=route.service, endpoint=route.endpoint, method=route.method,
            tool=route.tool, check=route.check, mode=route.mode,
        )
        return BindingResolution(status="bound", reason="Unique operator-owned source/handler/route",
                                 candidates=[route.id], binding=binding)
    except OSError:
        return BindingResolution(status="inconclusive", reason="Source snapshot unavailable")
    except UnicodeError:
        return BindingResolution(status="inconclusive", reason="Unsupported source encoding")
    except ValueError as exc:
        return BindingResolution(status="inconclusive", reason=str(exc))


def validate_action_binding(profile, action):
    """Recompute the complete binding at Validator and Executor boundaries."""
    binding = action.verification_binding
    if binding is None:
        raise ValueError("Operator verification binding is required")
    finding = Finding(id=binding.finding_id, source="binding", rule_id=binding.family,
                      title="Bound source", description="Operator verification",
                      file=binding.source_file, line_start=binding.line_start, line_end=binding.line_end)
    resolution = resolve_binding(profile, finding)
    if resolution.binding != binding:
        raise ValueError("Verification binding changed or is ambiguous: " + resolution.reason)
    expected = {"artifact_id": profile.artifact_id_for_path(binding.source_file, kind="javascript"),
                "line": binding.line_start, "check": binding.check}
    if binding.mode is not None:
        expected["mode"] = binding.mode
    if (action.target != profile.id or action.tool != binding.tool or action.service != binding.service
            or action.endpoint != binding.endpoint or action.parameters != expected):
        raise ValueError("Action differs from the operator verification binding")
    return binding
