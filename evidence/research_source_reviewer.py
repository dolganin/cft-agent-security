"""R06 independent SOURCE-condition reviewer. Never executes target or model code."""
import ast
import json
from hashlib import sha256

from security.verification_binding import syntax

WEAK = {"md5", "sha1", "sha-1"}
STRONG = {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512"}


def result(status, reason, **facts):
    return {"protocol": "weak_digest_call.v1", "status": status, "scope": "source_condition",
            "property": "explicit weak digest invocation", "runtime_exploit_verified": False,
            "reason": reason, "facts": facts}


def review(raw, file, start, end):
    if not 1 <= start <= end or end - start >= 160:
        return result("review_pending", "Invalid or oversized source range")
    try:
        if file.endswith(".py"):
            algorithms = _python(raw, start, end)
        elif file.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
            algorithms = _javascript(raw, file, start, end)
        else:
            return result("review_pending", "Unsupported source language")
    except (ValueError, SyntaxError, UnicodeError):
        return result("review_pending", "Malformed or ambiguous source/import/call")
    if len(algorithms) != 1 or algorithms[0] not in WEAK | STRONG:
        return result("review_pending", "Need one resolved literal digest invocation in the cited range")
    algorithm = algorithms[0]
    return result("confirmed" if algorithm in WEAK else "rejected",
        "Independent AST reviewer resolved the imported digest call", algorithm=algorithm,
        source_sha256=sha256(raw).hexdigest(), line_start=start, line_end=end,
        controls={"import_resolved": True, "literal_algorithm": True, "unique_call": True})


def _python(raw, start, end):
    tree = ast.parse(raw)
    modules, functions = set(), {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            modules.update(x.asname or x.name for x in node.names if x.name == "hashlib")
        if isinstance(node, ast.ImportFrom) and node.module == "hashlib":
            functions.update({x.asname or x.name: x.name for x in node.names if x.name in WEAK | STRONG | {"new"}})
    names = modules | set(functions)
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.arg in names:
            raise ValueError("Shadowed digest import")
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in names:
            raise ValueError("Reassigned digest import")
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name) and node.value.id in modules:
            raise ValueError("Reassigned imported hash method")
    algorithms = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not start <= node.lineno <= node.end_lineno <= end:
            continue
        name = None
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in modules:
            name = node.func.attr
        if isinstance(node.func, ast.Name):
            name = functions.get(node.func.id)
        if name == "new":
            algorithms.append(node.args[0].value.lower() if node.args and isinstance(node.args[0], ast.Constant)
                              and isinstance(node.args[0].value, str) else "unknown")
        elif name in WEAK | STRONG:
            algorithms.append(name)
    return algorithms


def _javascript(raw, file, start, end):
    tree, _ = syntax(raw, file, strict=True)
    modules, functions = set(), set()
    for node in tree.root_node.named_children:
        if node.type != "import_statement":
            continue
        if any(raw[child.start_byte:child.end_byte] == b"type" for child in node.children):
            continue
        source = node.child_by_field_name("source")
        if source is None or raw[source.start_byte:source.end_byte].decode().strip("\"'") not in {"crypto", "node:crypto"}:
            continue
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for item in clause.named_children:
                if item.type == "identifier":
                    modules.add(raw[item.start_byte:item.end_byte].decode())
                elif item.type == "namespace_import":
                    modules.update(raw[c.start_byte:c.end_byte].decode() for c in item.named_children if c.type == "identifier")
                elif item.type == "named_imports":
                    for spec in item.named_children:
                        name, alias = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                        if name and raw[name.start_byte:name.end_byte] == b"createHash":
                            bound = alias or name
                            functions.add(raw[bound.start_byte:bound.end_byte].decode())
    aliases = modules | functions
    nodes, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(node.named_children)
        if node.type in {"variable_declarator", "assignment_expression", "required_parameter", "optional_parameter"}:
            bound = node.child_by_field_name("name") or node.child_by_field_name("left") or node.child_by_field_name("pattern")
            if bound:
                assigned = raw[bound.start_byte:bound.end_byte].decode()
                if assigned in aliases or any(assigned.startswith((alias + ".", alias + "[")) for alias in modules):
                    raise ValueError("Shadowed/reassigned crypto import or method")
        if node.type == "formal_parameters" and any(raw[c.start_byte:c.end_byte].decode() in aliases for c in node.named_children):
            raise ValueError("Shadowed crypto parameter")
    algorithms = []
    for node in nodes:
        if node.type != "call_expression" or not start <= node.start_point.row + 1 <= node.end_point.row + 1 <= end:
            continue
        function, args = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        known = function and function.type == "identifier" and raw[function.start_byte:function.end_byte].decode() in functions
        if function and function.type == "member_expression":
            obj, prop = function.child_by_field_name("object"), function.child_by_field_name("property")
            known = bool(obj and prop and raw[obj.start_byte:obj.end_byte].decode() in modules
                         and raw[prop.start_byte:prop.end_byte] == b"createHash")
        if known:
            argument = args.named_children[0] if args and args.named_children else None
            algorithms.append(raw[argument.start_byte:argument.end_byte].decode()[1:-1].lower()
                              if argument and argument.type == "string" else "unknown")
    return algorithms


def main():
    import sys
    request = json.loads(sys.stdin.buffer.read(1048577))
    raw = request["source"].encode()
    print(json.dumps(review(raw, request["file"], request["line_start"], request["line_end"])))


if __name__ == "__main__":
    main()
