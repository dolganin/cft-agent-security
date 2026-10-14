"""Bounded, non-executing inventory of direct Express route registrations."""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePosixPath

from schemas.discovery import ProjectDiscoveryResult
from schemas.scout import CandidateFinding
from schemas.source_map import (
    ExpressMiddlewareRegistration,
    ExpressRouteRegistration,
    ExpressSourceMap,
)
from tools.repository_source import RepositorySource

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "all"}
_DELIMITERS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = {value: key for key, value in _DELIMITERS.items()}
_MAX_TOKENS_PER_FILE = 100_000
_MAX_ROUTES = 1_024
_MAX_MOUNTS = 2_048


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    start: int
    end: int
    line: int


def build_express_source_map(
    inventory: ProjectDiscoveryResult, *, include_oracle_controllers: bool = True,
) -> ExpressSourceMap:
    """Index statically recognizable registrations; never infer authorization."""
    # The default preserves the frozen A02 catalog's analyzed-file inventory.
    # Every live Scout/API call must explicitly opt out of answer-serving files.
    source = RepositorySource(inventory, include_oracle_controllers=include_oracle_controllers)
    contents = {path: "\n".join(source.lines[path]) for path in source.files}
    tokenized: dict[str, list[_Token]] = {}
    unsupported: list[str] = []
    bindings: dict[str, dict[str, str | None]] = {}
    for path, content in contents.items():
        if PurePosixPath(path).suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            continue
        tokens, truncated = _tokenize(content)
        tokenized[path] = tokens
        if truncated:
            unsupported.append(path)
        bindings[path] = _import_bindings(path, tokens, set(contents))

    routes: list[ExpressRouteRegistration] = []
    mounts: list[ExpressMiddlewareRegistration] = []
    dynamic_routes = 0
    omitted_routes = 0
    omitted_mounts = 0

    for path, tokens in tokenized.items():
        content = contents[path]
        line_offsets = [index for index, char in enumerate(content) if char == "\n"]
        apps, routers = _framework_receivers(tokens)
        imported = bindings.get(path, {})
        prior_mounts: list[ExpressMiddlewareRegistration] = []
        order = 0
        index = 0
        while index + 3 < len(tokens):
            receiver, dot, method, opening = tokens[index:index + 4]
            if (
                receiver.kind != "identifier"
                or dot.value != "."
                or method.kind != "identifier"
                or opening.value != "("
            ):
                index += 1
                continue
            is_app = receiver.value in apps
            is_router = receiver.value in routers
            if not (is_app or is_router):
                index += 1
                continue
            if method.value not in _ROUTE_METHODS and method.value != "use":
                index += 1
                continue
            arguments, closing = _call_arguments(tokens, index + 3)
            if arguments is None:
                index += 1
                continue
            order += 1
            line_start = receiver.line
            line_end = _line_at(line_offsets, tokens[closing].end)
            method_name = method.value

            if method_name == "use":
                has_path, paths = _static_paths(arguments[0], tokens) if arguments else (False, [])
                if has_path:
                    path_kind = "static"
                    middleware_args = arguments[1:]
                elif len(arguments) > 1 and _looks_like_explicit_path(arguments[0], tokens):
                    path_kind = "dynamic"
                    middleware_args = arguments[1:]
                else:
                    path_kind = "global"
                    middleware_args = arguments
                middleware = _argument_labels(content, tokens, middleware_args)
                for mount_path in paths or [None]:
                    entry = ExpressMiddlewareRegistration(
                        id=_stable_id(path, "use", mount_path, middleware, line_start, order),
                        file=path,
                        receiver=receiver.value,
                        mount_path=mount_path,
                        path_is_static=path_kind != "dynamic",
                        line_start=line_start,
                        registration_order=order,
                        middleware=middleware,
                    )
                    if len(mounts) < _MAX_MOUNTS:
                        mounts.append(entry)
                    else:
                        omitted_mounts += 1
                    prior_mounts.append(entry)
                index = closing + 1
                continue

            has_path, paths = _static_paths(arguments[0], tokens) if arguments else (False, [])
            middleware = _argument_labels(content, tokens, arguments[1:])
            handlers = sorted({
                imported[token.value]
                for start, stop in arguments[1:]
                for token in tokens[start:stop]
                if token.kind == "identifier" and imported.get(token.value)
            })
            paths_to_emit: list[str | None] = paths if has_path else [None]
            for route_path in paths_to_emit:
                if not has_path:
                    dynamic_routes += 1
                applicable_mounts = [
                    item for item in prior_mounts
                    if item.receiver == receiver.value
                    and _mount_may_precede(item, route_path)
                ][-8:]
                prior_descriptions = [
                    (f"{item.file}:{item.line_start} {item.mount_path or '/'} "
                     f"{' | '.join(item.middleware[:4])}")[:256]
                    for item in applicable_mounts
                ]
                entry = ExpressRouteRegistration(
                    id=_stable_id(path, method_name, route_path, middleware, line_start, order),
                    file=path,
                    receiver=receiver.value,
                    method=method_name,
                    path=route_path,
                    path_is_static=has_path,
                    line_start=line_start,
                    line_end=line_end,
                    registration_order=order,
                    middleware=middleware,
                    handler_files=handlers,
                    middleware_before=prior_descriptions,
                    service_id=inventory.resolve_component(path),
                )
                if len(routes) < _MAX_ROUTES:
                    routes.append(entry)
                else:
                    omitted_routes += 1
            index = closing + 1

    return ExpressSourceMap(
        analyzed_files=sorted(tokenized),
        routes=routes,
        middleware_mounts=mounts,
        dynamic_routes=dynamic_routes,
        omitted_routes=omitted_routes,
        omitted_middleware_mounts=omitted_mounts,
        unsupported_files=sorted(set(unsupported)),
    )


def link_candidates_to_routes(
    candidates: list[CandidateFinding], source_map: ExpressSourceMap,
) -> list[dict]:
    """Link source candidates to route registrations without inferring protection."""
    links = []
    for candidate in sorted(
        candidates,
        key=lambda item: (
            item.file, item.line_start or 0, item.rule_id, item.line_end or 0,
        ),
    ):
        matches: list[tuple[ExpressRouteRegistration, str]] = []
        for route in source_map.routes:
            if (candidate.file == route.file and candidate.line_start is not None
                    and route.line_start <= candidate.line_start <= route.line_end):
                matches.append((route, "route_registration"))
            elif candidate.file in route.handler_files:
                matches.append((route, "imported_handler_file"))
            elif candidate.file == route.file and candidate.line_start is None:
                matches.append((route, "same_file_without_line"))
        matches.sort(key=lambda match: (match[0].file, match[0].line_start, match[0].id))
        selected = matches[:16]
        links.append({
            "candidate": {
                "rule_id": candidate.rule_id,
                "file": candidate.file,
                "line_start": candidate.line_start,
                "line_end": candidate.line_end,
            },
            "binding_status": (
                "unmapped" if not matches else "unique" if len(matches) == 1 else "ambiguous"
            ),
            "truncated": len(matches) > len(selected),
            "authorization_assessment": "unknown",
            "routes": [
                {
                    "route_id": route.id,
                    "match_basis": basis,
                    "file": route.file,
                    "line_start": route.line_start,
                    "method": route.method,
                    "path": route.path,
                    "path_is_static": route.path_is_static,
                    "receiver": route.receiver,
                    "registered_arguments": route.middleware,
                    "middleware_before": route.middleware_before,
                }
                for route, basis in selected
            ],
            "note": (
                "Registration names and order are source hints only; the adapter does not "
                "determine whether authentication or authorization is enforced."
            ),
        })
    return links


def _tokenize(source: str) -> tuple[list[_Token], bool]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    length = len(source)
    truncated = False
    while index < length:
        char = source[index]
        if char.isspace():
            if char == "\n":
                line += 1
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = length if end < 0 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            stop = length if end < 0 else end + 2
            line += source.count("\n", index, stop)
            index = stop
            continue
        start = index
        start_line = line
        if char in "'\"`":
            quote = char
            index += 1
            value: list[str] = []
            interpolated = False
            while index < length:
                current = source[index]
                if current == "\\" and index + 1 < length:
                    value.extend((current, source[index + 1]))
                    index += 2
                    continue
                if quote == "`" and source.startswith("${", index):
                    interpolated = True
                if current == quote:
                    index += 1
                    break
                if current == "\n":
                    line += 1
                value.append(current)
                index += 1
            kind = "template" if quote == "`" and interpolated else "string"
            tokens.append(_Token(kind, "".join(value), start, index, start_line))
        elif char.isalpha() or char in "_$":
            index += 1
            while index < length and (source[index].isalnum() or source[index] in "_$"):
                index += 1
            tokens.append(_Token("identifier", source[start:index], start, index, start_line))
        elif char.isdigit():
            index += 1
            while index < length and (source[index].isalnum() or source[index] in "._"):
                index += 1
            tokens.append(_Token("number", source[start:index], start, index, start_line))
        elif char == "/" and _starts_regex(tokens):
            index += 1
            in_class = False
            while index < length:
                current = source[index]
                if current == "\\":
                    index += 2
                    continue
                if current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    index += 1
                    while index < length and source[index].isalpha():
                        index += 1
                    break
                elif current == "\n":
                    break
                index += 1
            tokens.append(_Token("regex", "", start, index, start_line))
        else:
            pair = source[index:index + 2]
            value = pair if pair in {"=>", "?.", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "..."} else char
            index += len(value)
            tokens.append(_Token("punct", value, start, index, start_line))
        if len(tokens) >= _MAX_TOKENS_PER_FILE:
            truncated = index < length
            break
    return tokens, truncated


def _starts_regex(tokens: list[_Token]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1].value
    return previous in {"=", "(", "[", "{", ",", ":", ";", "!", "?", "=>", "return", "case"}


def _framework_receivers(tokens: list[_Token]) -> tuple[set[str], set[str]]:
    apps: set[str] = set()
    routers: set[str] = set()
    for index, token in enumerate(tokens):
        if token.value not in {"const", "let", "var"} or index + 2 >= len(tokens):
            continue
        name = tokens[index + 1]
        if name.kind != "identifier":
            continue
        stop = min(len(tokens), index + 40)
        equals = next((i for i in range(index + 2, stop) if tokens[i].value == "="), None)
        if equals is None:
            continue
        init = tokens[equals + 1:stop]
        if any(
            init[pos].value == "express" and init[pos + 1].value == "."
            and init[pos + 2].value == "Router"
            for pos in range(max(0, len(init) - 2))
        ) or any(init[pos].value == "Router" and init[pos + 1].value == "("
                 for pos in range(max(0, len(init) - 1))):
            routers.add(name.value)
        elif any(init[pos].value == "express" and init[pos + 1].value == "("
                 for pos in range(max(0, len(init) - 1))):
            apps.add(name.value)
    return apps, routers


def _call_arguments(
    tokens: list[_Token], opening: int,
) -> tuple[list[tuple[int, int]] | None, int]:
    arguments: list[tuple[int, int]] = []
    stack: list[str] = []
    argument_start = opening + 1
    for index in range(opening + 1, len(tokens)):
        value = tokens[index].value
        if value in _DELIMITERS:
            stack.append(_DELIMITERS[value])
        elif value in _CLOSERS:
            if not stack:
                if value != ")":
                    return None, index
                if argument_start < index:
                    arguments.append((argument_start, index))
                return arguments, index
            if stack.pop() != value:
                return None, index
        elif value == "," and not stack:
            if argument_start < index:
                arguments.append((argument_start, index))
            argument_start = index + 1
    return None, len(tokens) - 1


def _static_paths(
    argument: tuple[int, int] | None, tokens: list[_Token],
) -> tuple[bool, list[str]]:
    if argument is None:
        return False, []
    start, end = argument
    selected = tokens[start:end]
    if len(selected) == 1 and selected[0].kind == "string":
        value = selected[0].value
        if _is_static_path(value):
            return True, [value]
    if len(selected) >= 3 and selected[0].value == "[" and selected[-1].value == "]":
        values = [token.value for token in selected[1:-1] if token.kind == "string"]
        punctuation_only = all(token.kind == "string" or token.value == ","
                               for token in selected[1:-1])
        if values and punctuation_only and all(_is_static_path(value) for value in values):
            return True, values[:16]
    return False, []


def _is_static_path(value: str) -> bool:
    return (
        value.startswith("/") and len(value) <= 512 and "\\" not in value
        and "${" not in value and "\n" not in value and "\r" not in value
    )


def _argument_labels(
    content: str, tokens: list[_Token], arguments: list[tuple[int, int]],
) -> list[str]:
    labels = []
    for start, end in arguments[:8]:
        if start >= end:
            continue
        expression = content[tokens[start].start:tokens[end - 1].end].strip()
        labels.append(expression[:120])
    return labels


def _import_bindings(
    current_file: str, tokens: list[_Token], known_files: set[str],
) -> dict[str, str | None]:
    bindings: dict[str, str | None] = {}
    index = 0
    while index < len(tokens):
        if tokens[index].value != "import" or index + 1 >= len(tokens) or tokens[index + 1].value == "(":
            index += 1
            continue
        stop = min(len(tokens), index + 64)
        from_index = next((i for i in range(index + 1, stop) if tokens[i].value == "from"), None)
        if from_index is None or from_index + 1 >= len(tokens):
            index += 1
            continue
        module = tokens[from_index + 1]
        if module.kind != "string" or not module.value.startswith("."):
            index = from_index + 2
            continue
        target = _resolve_import(current_file, module.value, known_files)
        clause = tokens[index + 1:from_index]
        names: list[str] = []
        if clause and clause[0].kind == "identifier" and clause[0].value != "type":
            names.append(clause[0].value)
        for pos, item in enumerate(clause[:-2]):
            if item.value == "*" and clause[pos + 1].value == "as":
                names.append(clause[pos + 2].value)
        open_brace = next((pos for pos, item in enumerate(clause) if item.value == "{"), None)
        if open_brace is not None:
            for part in _split_import_names(clause[open_brace + 1:]):
                identifiers = [item.value for item in part if item.kind == "identifier"]
                identifiers = [name for name in identifiers if name != "type"]
                if identifiers:
                    names.append(identifiers[-1] if "as" in identifiers else identifiers[0])
        for name in names:
            if name in bindings and bindings[name] != target:
                bindings[name] = None
            else:
                bindings[name] = target
        index = from_index + 2
    return bindings


def _resolve_import(current_file: str, module: str, known_files: set[str]) -> str | None:
    base = PurePosixPath(current_file).parent.joinpath(module)
    parts: list[str] = []
    for part in base.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part not in {".", ""}:
            parts.append(part)
    stem = PurePosixPath(*parts).as_posix()
    choices = [stem, *(stem + suffix for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")),
               *(stem + "/index" + suffix for suffix in (".ts", ".tsx", ".js", ".jsx"))]
    matches = [choice for choice in choices if choice in known_files]
    return matches[0] if len(matches) == 1 else None


def _mount_may_precede(mount: ExpressMiddlewareRegistration, route_path: str | None) -> bool:
    if mount.mount_path is None:
        return mount.path_is_static and route_path is not None
    prefix = mount.mount_path
    if route_path is None or any(char in prefix for char in ("*", "?", "(", ")", "\\")):
        return False
    if ":" in prefix:
        return False
    return route_path == prefix or route_path.startswith(prefix.rstrip("/") + "/")


def _looks_like_explicit_path(
    argument: tuple[int, int], tokens: list[_Token],
) -> bool:
    start, end = argument
    selected = tokens[start:end]
    if not selected:
        return False
    if selected[0].value in {"function", "(", "async"} or any(
        item.value == "=>" for item in selected
    ):
        return False
    return selected[0].kind == "identifier" and len(selected) == 1


def _split_import_names(tokens: list[_Token]) -> list[list[_Token]]:
    parts: list[list[_Token]] = []
    start = 0
    for index, token in enumerate(tokens):
        if token.value == ",":
            if start < index:
                parts.append(tokens[start:index])
            start = index + 1
        elif token.value == "}":
            if start < index:
                parts.append(tokens[start:index])
            break
    return parts


def _stable_id(file: str, method: str, path: str | None, middleware: list[str], line: int, order: int) -> str:
    key = "|".join((file, method, path or "<dynamic>", ",".join(middleware), str(line), str(order)))
    return "express-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def _line_at(newlines: list[int], offset: int) -> int:
    return bisect_right(newlines, offset) + 1
