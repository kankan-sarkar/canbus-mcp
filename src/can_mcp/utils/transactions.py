"""Atomic file writes & .bak rollback manager.

Every mutation tool must back up the pre-existing file before touching it
(Gate 2.1) and must never leave a partially-written file on disk if the
process is interrupted mid-write.
"""
from __future__ import annotations

from pathlib import Path

from can_mcp.config import BACKUP_SUFFIX


def backup_path(target: Path) -> Path:
    return target.with_name(target.name + BACKUP_SUFFIX)


def write_text_atomically(text: str, target: Path) -> Path | None:
    """Back up `target` (if it already exists) then atomically replace its
    contents with `text`. Returns the backup path, or None if `target` did
    not exist yet (nothing to back up).
    """
    backup = None
    if target.exists():
        backup = backup_path(target)
        backup.write_bytes(target.read_bytes())
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(text)
    tmp.replace(target)
    return backup


def commit_file_atomically(tmp_path: Path, target: Path) -> Path | None:
    """Back up `target` (if it exists) then atomically move an already-written
    `tmp_path` into place. For binary/third-party-library outputs (e.g.
    canmatrix format conversions) where the caller writes the tmp file
    itself rather than handing us text.
    """
    backup = None
    if target.exists():
        backup = backup_path(target)
        backup.write_bytes(target.read_bytes())
    tmp_path.replace(target)
    return backup
