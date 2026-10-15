"""Conservative cross-file AST proof of a direct unsalted password digest.

This proves a source property only. It never executes target code, handles a real
password, or turns an unavailable runtime check into a confirmed exploit.
"""
from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import Path

from evidence.research_source_reviewer import review
from security.source_paths import normalize_source_path
from security.verification_binding import syntax, tokens


def _walk(node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _text(raw, node):
    return raw[node.start_byte:node.end_byte].decode()


def _values(raw, node, file):
    values = []
    for value, _ in tokens(_text(raw, node), file):
        if value == ";":
            continue
        if value.startswith(("'", '"')):
            value = "literal:" + ast.literal_eval(value)
        values.append(value)
    return values


def _parameter(raw, node):
    parameters = node.child_by_field_name("parameters")
    if parameters is None or len(parameters.named_children) != 1:
        raise ValueError("Need one direct parameter")
    parameter = parameters.named_children[0]
    name = parameter.child_by_field_name("pattern") or parameter
    if name.type != "identifier":
        raise ValueError("Unsupported parameter")
    return _text(raw, name)


def _read(root, name, expected):
    name = normalize_source_path(name)
    path = root / name
    if path.is_symlink() or path.resolve(strict=True).relative_to(root).as_posix() != name:
        raise ValueError("Noncanonical source")
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576 or sha256(raw).hexdigest() != expected:
        raise ValueError("Source snapshot mismatch")
    return raw


def review_password_storage(*, root, model_file, helper_file, source_sha256):
    result = {"protocol": "direct_password_digest.source.v1", "scope": "source_condition",
        "property": "password setter directly stores an unsalted weak digest",
        "status": "review_pending", "runtime_exploit_verified": False,
        "source_sha256": {name: source_sha256[name] for name in (model_file, helper_file)
                          if name in source_sha256}}
    try:
        root = Path(root).resolve(strict=True)
        model = _read(root, model_file, source_sha256[model_file])
        helper = _read(root, helper_file, source_sha256[helper_file])
        model_tree, _ = syntax(model, model_file, strict=True)
        helper_tree, _ = syntax(helper, helper_file, strict=True)
        namespaces = []
        for node in model_tree.root_node.named_children:
            if node.type != "import_statement":
                continue
            source = node.child_by_field_name("source")
            if source is None:
                continue
            imported = ast.literal_eval(_text(model, source))
            if not imported.startswith("."):
                continue
            candidate = (root / model_file).parent / (imported + ".ts")
            if candidate.resolve().relative_to(root).as_posix() != helper_file:
                continue
            namespaces.extend(_text(model, child) for item in _walk(node)
                              if item.type == "namespace_import" for child in item.named_children
                              if child.type == "identifier")
        if len(namespaces) != 1:
            raise ValueError("No unique helper import")
        namespace = namespaces[0]
        for node in _walk(model_tree.root_node):
            if node.type in {"variable_declarator", "assignment_expression", "required_parameter", "optional_parameter"}:
                bound = (node.child_by_field_name("name") or node.child_by_field_name("left")
                         or node.child_by_field_name("pattern"))
                assigned = _text(model, bound) if bound is not None else ""
                if assigned == namespace or assigned.startswith((namespace + ".", namespace + "[")):
                    raise ValueError("Reassigned or shadowed helper")
        initializers = [node for node in _walk(model_tree.root_node)
                        if node.type == "call_expression"
                        and _text(model, node.child_by_field_name("function")) == "User.init"]
        if len(initializers) != 1:
            raise ValueError("No unique User initializer")
        arguments = initializers[0].child_by_field_name("arguments").named_children
        if not arguments or arguments[0].type != "object":
            raise ValueError("Unsupported model attributes")
        passwords = [node.child_by_field_name("value") for node in arguments[0].named_children
                     if node.type == "pair" and _text(model, node.child_by_field_name("key")) == "password"]
        if len(passwords) != 1 or passwords[0].type != "object":
            raise ValueError("No unique password field")
        setters = [node for node in passwords[0].named_children if node.type == "method_definition"
                   and _text(model, node.child_by_field_name("name")) == "set"]
        if len(setters) != 1:
            raise ValueError("No unique password setter")
        setter = setters[0]
        parameter = _parameter(model, setter)
        expected = ["{", "this", ".", "setDataValue", "(", "literal:password", ",", namespace,
                    ".", "hash", "(", parameter, ")", ")", "}"]
        if _values(model, setter.child_by_field_name("body"), model_file) != expected:
            raise ValueError("Setter is not a direct helper-to-password store")
        helpers = [node.child_by_field_name("value") for node in _walk(helper_tree.root_node)
                   if node.type == "variable_declarator"
                   and _text(helper, node.child_by_field_name("name")) == "hash"]
        if len(helpers) != 1 or helpers[0].type != "arrow_function":
            raise ValueError("No unique hash helper")
        function = helpers[0]
        declaration = function.parent.parent
        if (declaration.type != "lexical_declaration" or declaration.parent.type != "export_statement"
                or not _text(helper, declaration).startswith("const ")):
            raise ValueError("Helper must be an exported const")
        for node in _walk(helper_tree.root_node):
            if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
                left = node.child_by_field_name("left") or node.child_by_field_name("argument")
                if left is not None and _text(helper, left) == "hash":
                    raise ValueError("Reassigned helper")
        start, end = function.start_point.row + 1, function.end_point.row + 1
        digest_review = review(helper, helper_file, start, end)
        if digest_review["status"] != "confirmed":
            raise ValueError("No independently resolved weak digest")
        body = _values(helper, function.child_by_field_name("body"), helper_file)
        data = _parameter(helper, function)
        algorithm = digest_review["facts"]["algorithm"]
        # Exactly one argument reaches exactly one update. Salts, transforms,
        # extra updates, wrappers or KDFs require another protocol, not a guess.
        if len(body) != 16 or body[1:] != [".", "createHash", "(", "literal:" + algorithm, ")", ".",
                "update", "(", data, ")", ".", "digest", "(", "literal:hex", ")"]:
            raise ValueError("Not a direct unsalted digest chain")
        # Recheck bytes after parsing to avoid retaining a stale snapshot proof.
        for name in (model_file, helper_file):
            _read(root, name, source_sha256[name])
        result.update(status="confirmed", reason="Bound AST setter/import/helper/digest/storage chain",
            algorithm=algorithm, setter={"file": model_file, "line_start": setter.start_point.row + 1,
                "line_end": setter.end_point.row + 1},
            helper={"file": helper_file, "line_start": start, "line_end": end},
            controls={"helper_import_resolved": True, "direct_parameter": True,
                "password_storage_bound": True, "single_unsalted_digest_chain": True})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, SyntaxError):
        result["reason"] = "Missing, changed, ambiguous or unsupported AST storage chain"
    return result
