from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any

from .canonical import DEFAULT_MAX_JSON_BYTES, CanonicalJsonError, strict_json_loads


class StableReadError(RuntimeError):
    pass


def read_stable_json(path: str | Path, *, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> Any:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise StableReadError("max_bytes must be a non-negative integer")
    target = Path(path)
    try:
        before = target.lstat()
    except FileNotFoundError as error:
        raise StableReadError("input file does not exist") from error
    if stat.S_ISLNK(before.st_mode):
        raise StableReadError("symbolic-link inputs are forbidden")
    if not stat.S_ISREG(before.st_mode):
        raise StableReadError("input must be a regular file")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise StableReadError("failed to open input without following links") from error

    try:
        opened = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_opened = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if identity_opened != identity_before:
            raise StableReadError("input identity or metadata changed before read")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise StableReadError("input exceeds the configured byte limit")
        after = os.fstat(descriptor)
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_opened != identity_after:
            raise StableReadError("input changed while it was being read")
    finally:
        os.close(descriptor)

    try:
        return strict_json_loads(payload, max_bytes=max_bytes)
    except CanonicalJsonError as error:
        raise StableReadError(str(error)) from error
