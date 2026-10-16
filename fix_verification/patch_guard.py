"""Fail-closed defensive source shapes, never a remediation verdict."""
import re

from fix_verification.review import validate_sequelize_search_proposal


def defensive_shape(family: str, canonical: str):
    if family == "sql-search":
        # Existing deterministic policy preserves SELECT, deletedAt, ORDER BY
        # and actual Sequelize bind/replacements semantics. No extra statement.
        validate_sequelize_search_proposal(canonical)
        return
    removed, added = [], []
    for line in canonical.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].split("// vuln-code-snippet", 1)[0].strip())
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].split("// vuln-code-snippet", 1)[0].strip())
    # Deliberately narrow C02 policy. The model writes the real diff; the gate
    # accepts an exact equality repair, preserving loop, allowlist and handler.
    if (family != "redirect-allowlist" or len(removed) != 1 or len(added) != 1
            or removed[0] != "allowed = allowed || url.includes(allowedUrl)"
            or not re.fullmatch(r"allowed\s*=\s*allowed\s*\|\|\s*(?:url\s*===\s*allowedUrl|allowedUrl\s*===\s*url);?", added[0])):
        raise ValueError("unsupported_defensive_shape")
