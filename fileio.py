"""
Small file-writing helpers shared by the cache and the web report store.

* ``private_dir`` creates a directory that only its owner can enter (POSIX).
* ``atomic_write_text`` writes through a temporary file in the same directory
  and ``os.replace``: a reader sees the old file or the new one, never a
  half-written one, and the file is owner-only (POSIX). Temporary files are
  named ``.<target-name>.<random>.partial`` so maintenance can recognise a
  leftover of an interrupted write.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
TEMP_SUFFIX = ".partial"


def private_dir(path: Path) -> None:
    """Create *path* (and parents) if missing; the directory itself is owner-only."""
    path.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    """Replace *path* with *text* atomically (UTF-8, owner-only)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=TEMP_SUFFIX)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
