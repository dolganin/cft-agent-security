"""Repository-relative source paths, independent of scanner/platform spelling."""
from pathlib import Path, PurePosixPath, PureWindowsPath


def normalize_source_path(value: str, repository_root: str | Path | None = None) -> str:
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError("Empty or control-character source path")
    spelling = value.replace("\\", "/")
    root_text = str(repository_root).replace("\\", "/") if repository_root is not None else None
    if root_text is not None and not PureWindowsPath(root_text).drive:
        root_text = str(Path(root_text).resolve())
    windows = PureWindowsPath(value)
    path = PurePosixPath(spelling)
    if ".." in path.parts:
        raise ValueError("Source path traversal is not permitted")
    if windows.drive or path.is_absolute():
        if repository_root is None:
            raise ValueError("Absolute source path requires a trusted repository root")
        root_windows = PureWindowsPath(root_text)
        if windows.drive:
            if not windows.is_absolute() or not root_windows.is_absolute():
                raise ValueError("Drive-relative or foreign source path")
            # Windows containment is case-insensitive; returned spelling is not folded.
            prefix = root_windows.parts
            if tuple(p.casefold() for p in windows.parts[:len(prefix)]) != tuple(
                p.casefold() for p in prefix
            ):
                raise ValueError("Source path is outside the repository")
            spelling = "/".join(windows.parts[len(prefix):])
        else:
            root = PurePosixPath(root_text)
            if not root.is_absolute():
                raise ValueError("Absolute source path requires an absolute root")
            try:
                spelling = path.relative_to(root).as_posix()
            except ValueError as exc:
                raise ValueError("Source path is outside the repository") from exc
    parts = PurePosixPath(spelling).parts
    if not parts or any(":" in part for part in parts):
        raise ValueError("Invalid source path or alternate data stream")
    relative = PurePosixPath(*parts).as_posix()
    if relative == ".":
        raise ValueError("Source path must name a file")
    if repository_root is not None:
        native_root = Path(root_text)
        # Foreign Windows roots can be normalized offline but never read on POSIX.
        if native_root.is_absolute():
            root = native_root.resolve()
            current = root
            for part in parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError("Linked source paths are not permitted")
            if not current.resolve().is_relative_to(root):
                raise ValueError("Source path escaped the repository")
    return relative
