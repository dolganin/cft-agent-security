"""Bounded source inspection. Model requests never become commands or host paths."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from schemas.discovery import ProjectDiscoveryResult
from security.source_paths import normalize_source_path

_SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}
_EXCLUDED_PARTS = {
    ".git", ".venv", "node_modules", "dist", "build", "vendor", "coverage",
    "codefixes", "test", "tests", "__tests__", "__pycache__",
    "hacking-instructor", "hackinginstructor", "benchmark", "ground-truth",
    "ground_truth", "solutions",
}
_INTEREST = re.compile(
    r"\b(?:req\.(?:query|body|params)|request\.|router\.|app\.(?:get|post|put|delete)|"
    r"sequelize|query\(|execute\(|sendFile|serveIndex|jwt|authorize|authenticate|"
    r"dangerouslySetInnerHTML|innerHTML|render\(|password|isAdmin)"
)
_IMPORT = re.compile(r"(?:from\s*|require\(\s*)['\"](\.[^'\"]+)['\"]")
_SECRET_LITERAL = re.compile(
    r"(?i)(\b(?:[\w]*(?:password|passwd|secret|token|api_key|apikey)|SECRET_KEY)"
    r"\b[\"']?\s*[:=]\s*)([\"'])(.*?)(\2)"
)
_CREDENTIAL = re.compile(r"\bsk-[a-zA-Z0-9_-]{16,}|\beyJ[\w-]+\.[\w-]+\.[\w-]+")


def _source_path(file: str) -> bool:
    path = PurePosixPath(file)
    parts = {part.casefold() for part in path.parts}
    return (
        not path.is_absolute() and ".." not in path.parts
        and path.suffix in _SOURCE_SUFFIXES
        and not parts.intersection(_EXCLUDED_PARTS)
        and not path.name.endswith((".spec.ts", ".spec.js", ".test.ts", ".test.js", ".d.ts"))
        and not path.name.startswith("test_")
    )


def _safe_line(line: str) -> str:
    # Evaluation hints are not application behavior; retain physical line numbering.
    if "vuln-code-snippet" in line:
        line = line.split("// vuln-code-snippet", 1)[0]
        if "vuln-code-snippet" in line:
            line = ""
    line = _SECRET_LITERAL.sub(r"\1\2<redacted>\2", line)
    return _CREDENTIAL.sub("<redacted>", line)[:2_000]


class RepositorySource:
    """A finite text corpus selected exclusively from trusted discovery paths."""

    def __init__(self, inventory: ProjectDiscoveryResult):
        self.root = inventory.repository_root.resolve()
        self.lines: dict[str, list[str]] = {}
        self.skipped: dict[str, int] = {}
        total_bytes = 0
        paths = sorted(set(inventory.project_files), key=lambda p: (self._path_rank(p), p))
        for file in paths:
            try:
                file = normalize_source_path(file, self.root)
            except ValueError:
                self._skip("unsafe_path")
                continue
            if not _source_path(file):
                self._skip("outside_application_source")
                continue
            if len(self.lines) >= 256 or total_bytes >= 4_194_304:
                self._skip("index_budget")
                continue
            path = self.root / file
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(self.root) or path.is_symlink():
                    self._skip("unsafe_path")
                    continue
                # Reject linked parent directories even when they point inside the root.
                if any(parent.is_symlink() for parent in path.parents if parent != self.root):
                    self._skip("unsafe_path")
                    continue
                if not resolved.is_file():
                    self._skip("not_file")
                    continue
                with resolved.open("rb") as stream:
                    raw = stream.read(min(131_073, 4_194_304 - total_bytes + 1))
                if len(raw) > 131_072 or total_bytes + len(raw) > 4_194_304 or b"\0" in raw:
                    self._skip("large_or_binary")
                    continue
                total_bytes += len(raw)
                self.lines[file] = [_safe_line(line) for line in raw.decode(
                    "utf-8-sig", errors="replace"
                ).splitlines()]
            except (OSError, ValueError):
                self._skip("unreadable")
        self.files = sorted(self.lines, key=lambda p: (
            -min(sum(bool(_INTEREST.search(line)) for line in self.lines[p]), 30),
            self._path_rank(p), p,
        ))

    @staticmethod
    def _path_rank(file: str) -> int:
        path = PurePosixPath(file)
        if set(path.parts).intersection({"routes", "controllers", "middleware", "api"}):
            return 0
        if path.stem in {"server", "app", "index", "main"}:
            return 1
        return 2

    def _skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def read(self, file: str, start: int = 1, end: int = 100) -> dict:
        if file not in self.lines or start < 1 or end < start:
            raise ValueError("Unknown source path or invalid line range")
        lines = self.lines[file]
        end = min(end, start + 159, len(lines))
        if start > end:
            raise ValueError("Line range outside source")
        selected = []
        size = 0
        for number in range(start, end + 1):
            text = f"{number}: {lines[number - 1]}"
            if size + len(text) > 10_000:
                break
            selected.append(text)
            size += len(text) + 1
        if not selected:
            raise ValueError("Empty source window")
        return {"file": file, "line_start": start, "line_end": start + len(selected) - 1,
                "content": "\n".join(selected)}

    def search(self, query: str) -> list[dict]:
        if not query.strip() or len(query) > 120:
            return []
        matches = []
        for file in self.files:
            for number, line in enumerate(self.lines[file], start=1):
                if query.casefold() in line.casefold():
                    matches.append({"file": file, "line": number, "text": line[:400]})
                    if len(matches) == 16:
                        return matches
        return matches

    def related_files(self, file: str) -> list[str]:
        related = []
        for match in _IMPORT.finditer("\n".join(self.lines.get(file, []))):
            base = PurePosixPath(file).parent / match[1]
            # Normalize relative imports without permitting model-selected host access.
            parts: list[str] = []
            for part in base.parts:
                if part == "..":
                    if parts:
                        parts.pop()
                elif part != ".":
                    parts.append(part)
            stem = "/".join(parts)
            choices = [stem, *(stem + ext for ext in sorted(_SOURCE_SUFFIXES)),
                       stem + "/index.ts", stem + "/index.js"]
            related.extend(p for p in choices if p in self.lines)
        return list(dict.fromkeys(related))[:8]
