"""Read-only exploration schedules and explicit gaps in successfully reviewed source."""

from collections import deque

from schemas.source_map import ExpressSourceMap
from tools.repository_source import RepositorySource


def source_schedule(
    source: RepositorySource, source_map: ExpressSourceMap | None, mode: str,
) -> deque:
    files = source.files
    if mode == "handlers":
        handlers = {f for r in (source_map.routes if source_map else [])
                    for f in r.handler_files}
        rank = {f: i for i, f in enumerate(files)}
        files = sorted(files, key=lambda f: (
            f not in handlers, source._path_rank(f), rank[f],
        ))
    fallback = [(f, start, start + 159)
                for start in range(1, max(map(len, source.lines.values()), default=0) + 1, 160)
                for f in files if start <= len(source.lines[f])]
    if mode == "round_robin":
        return deque(fallback)
    focused = {f: source.focused_windows(f) for f in files}
    initial = [window for i in range(4) for f in files for window in focused[f][i:i + 1]]
    if source_map:
        initial.extend((r.file, max(1, r.line_start - 12), r.line_end + 20)
                       for r in source_map.routes if r.file in source.lines)
    return deque(dict.fromkeys([*initial, *fallback]))


def unread_coverage(source: RepositorySource, reviewed: dict) -> dict:
    gaps = []
    full = 0
    for file, lines in source.lines.items():
        cursor = 1
        before = len(gaps)
        for start, end in sorted(reviewed.get(file, [])):
            if start > cursor:
                gaps.append({"file": file, "line_start": cursor, "line_end": start - 1})
            cursor = max(cursor, end + 1)
        if cursor <= len(lines):
            gaps.append({"file": file, "line_start": cursor, "line_end": len(lines)})
        if len(gaps) == before:
            full += 1
    return {"unread_ranges": gaps, "fully_reviewed_files": full,
            "unread_files": [f for f in source.files if source.lines[f] and f not in reviewed]}
