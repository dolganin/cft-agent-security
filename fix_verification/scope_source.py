"""Bounded AST extraction for C01 evaluator qualification; never executes source."""
import json
from pathlib import Path

import tree_sitter_typescript
from tree_sitter import Language, Parser

from fix_verification.workspace import safe_file


def expressions(root: Path) -> dict:
    parser = Parser(Language(tree_sitter_typescript.language_typescript()))

    def read(file):
        raw = safe_file(root, file).read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError("Source exceeds evaluator budget")
        tree = parser.parse(raw)
        if tree.root_node.has_error:
            raise ValueError("Invalid TypeScript source")
        return raw, tree.root_node

    def walk(node):
        yield node
        for child in node.named_children:
            yield from walk(child)

    raw, tree = read("routes/search.ts")
    queries = [node for node in walk(tree) if node.type == "call_expression"
               and node.child_by_field_name("function") is not None
               and raw[node.child_by_field_name("function").start_byte:
                       node.child_by_field_name("function").end_byte] == b"models.sequelize.query"
               and b"criteria" in raw[node.start_byte:node.end_byte]]
    if len(queries) != 1:
        raise ValueError("Missing/ambiguous supported search query; ineligible source shape")
    sql = raw[queries[0].start_byte:queries[0].end_byte].decode()
    raw, tree = read("lib/insecurity.ts")
    parts = []
    allowlist = []
    for name in ("redirectAllowlist", "isRedirectAllowed"):
        found = [node for node in walk(tree) if node.type == "variable_declarator"
                 and node.child_by_field_name("name") is not None
                 and raw[node.child_by_field_name("name").start_byte:
                         node.child_by_field_name("name").end_byte] == name.encode()]
        if len(found) != 1:
            raise ValueError("Missing/ambiguous redirect declaration")
        node = found[0]
        data = raw[node.start_byte:node.end_byte]
        for annotation in sorted((n for n in walk(node) if n.type == "type_annotation"),
                                 key=lambda n: n.start_byte, reverse=True):
            start, end = annotation.start_byte-node.start_byte, annotation.end_byte-node.start_byte
            data = data[:start] + data[end:]
        parts.append("const " + data.decode() + ";")
        if name == "redirectAllowlist":
            for child in walk(node):
                if child.type == "string":
                    value = raw[child.start_byte+1:child.end_byte-1].decode()
                    allowlist.append(value)
    return {"sql": sql, "redirect": "\n".join(parts), "originalAllowlist": allowlist}


def write_expressions(root: Path, output: Path):
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(expressions(root)))
