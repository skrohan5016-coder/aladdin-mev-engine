from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .ledger import MAX_SEGMENT_BYTES, ObservationSegment, parse_segment, serialize_segment

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SegmentStorageError(RuntimeError):
    """Raised when immutable segment storage cannot be trusted."""


def _require_linux_nofollow() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SegmentStorageError("immutable segment storage requires Linux no-follow semantics")
    return os.O_NOFOLLOW


def _open_parent(path: Path) -> tuple[int, str]:
    if not path.name or path.name in {".", ".."}:
        raise SegmentStorageError("segment path must name a file")
    parent = path.parent if str(path.parent) else Path(".")
    if ".." in parent.parts:
        raise SegmentStorageError("parent traversal is forbidden for immutable segment storage")
    nofollow = _require_linux_nofollow()
    flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
    absolute = parent.is_absolute()
    descriptor: int | None = None
    try:
        descriptor = os.open("/" if absolute else ".", flags)
        parts = parent.parts[1:] if absolute else parent.parts
        for component in parts:
            if component in {"", "."}:
                continue
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise SegmentStorageError(
            "segment parent is unavailable or contains an untrusted link"
        ) from error
    if descriptor is None:  # defensive
        raise SegmentStorageError("failed to establish immutable segment parent")
    return descriptor, path.name


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise SegmentStorageError("short write while storing observation segment")
        offset += written


def _require_published_stat(info: os.stat_result, *, expected_size: int) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise SegmentStorageError("published segment is not a regular file")
    if info.st_size != expected_size:
        raise SegmentStorageError("published segment size does not match the sealed payload")
    if info.st_mode & 0o222:
        raise SegmentStorageError("published segment retains write permission")
    if info.st_nlink != 1:
        raise SegmentStorageError("published segment has an unexpected hard-link count")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_expected_sha256(value: str | None) -> None:
    if value is not None and (type(value) is not str or _SHA256.fullmatch(value) is None):
        raise SegmentStorageError("expected_payload_sha256 must be a lowercase SHA-256 digest or null")


def write_segment_once(path: str | Path, segment: ObservationSegment) -> str:
    target = Path(path)
    payload = serialize_segment(segment)
    parent_fd, name = _open_parent(target)
    temporary_name: str | None = None
    temporary_fd: int | None = None
    target_created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _require_linux_nofollow()
        for counter in range(128):
            candidate = f".{name}.{os.getpid()}.{counter}.tmp"
            try:
                temporary_fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None or temporary_name is None:
            raise SegmentStorageError("unable to allocate an immutable temporary segment file")
        _write_all(temporary_fd, payload)
        os.fsync(temporary_fd)
        before_publish = os.fstat(temporary_fd)
        if not stat.S_ISREG(before_publish.st_mode) or before_publish.st_nlink != 1:
            raise SegmentStorageError("temporary segment identity is not trustworthy")
        if before_publish.st_size != len(payload):
            raise SegmentStorageError("temporary segment size does not match the sealed payload")
        os.fchmod(temporary_fd, 0o400)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise SegmentStorageError(
                "segment path already exists; overwrite is forbidden"
            ) from error
        target_created = True
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if linked.st_nlink != 2 or linked.st_mode & 0o222 or linked.st_size != len(payload):
            raise SegmentStorageError("segment publication identity check failed")
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_name = None
        os.fsync(parent_fd)
        published = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require_published_stat(published, expected_size=len(payload))
        target_created = False
        return hashlib.sha256(payload).hexdigest()
    except OSError as error:
        raise SegmentStorageError("failed to store immutable observation segment") from error
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if target_created:
            try:
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def read_segment_stable(
    path: str | Path,
    *,
    expected_payload_sha256: str | None = None,
) -> ObservationSegment:
    _require_expected_sha256(expected_payload_sha256)
    target = Path(path)
    parent_fd, name = _open_parent(target)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | _require_linux_nofollow()
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino):
            raise SegmentStorageError("segment path changed while it was opened")
        if not stat.S_ISREG(before.st_mode):
            raise SegmentStorageError("segment source must be a regular file")
        if before.st_nlink != 1:
            raise SegmentStorageError("segment source has an unexpected hard-link count")
        if before.st_mode & 0o222:
            raise SegmentStorageError("segment source is not sealed read-only")
        if before.st_size <= 0 or before.st_size > MAX_SEGMENT_BYTES:
            raise SegmentStorageError("segment source size is outside the governed range")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                raise SegmentStorageError("segment source ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SegmentStorageError("segment source grew during read")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise SegmentStorageError("segment source changed during read")
        try:
            path_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as error:
            raise SegmentStorageError("segment path disappeared during read") from error
        if _identity(path_after) != _identity(after):
            raise SegmentStorageError("segment path identity changed during read")
        payload = b"".join(chunks)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        if expected_payload_sha256 is not None and payload_sha256 != expected_payload_sha256:
            raise SegmentStorageError("segment payload digest does not match its external anchor")
        return parse_segment(payload)
    except FileNotFoundError as error:
        raise SegmentStorageError("segment source does not exist") from error
    except OSError as error:
        raise SegmentStorageError("failed to read immutable observation segment") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
