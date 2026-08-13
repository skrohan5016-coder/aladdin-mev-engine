from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from typing import Any, NoReturn

DEFAULT_MAX_JSON_BYTES = 1_048_576
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_ITEMS = 100_000


class CanonicalJsonError(ValueError):
    """Raised when input cannot participate in canonical evidence."""


def _reject_float(value: str) -> NoReturn:
    raise CanonicalJsonError(f"floating-point numbers are forbidden: {value}")


def _reject_constant(value: str) -> NoReturn:
    raise CanonicalJsonError(f"non-finite JSON constants are forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _validate_tree(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    item_counter: list[int],
    max_items: int,
) -> None:
    if depth > max_depth:
        raise CanonicalJsonError("maximum JSON nesting depth exceeded")
    item_counter[0] += 1
    if item_counter[0] > max_items:
        raise CanonicalJsonError("maximum JSON item count exceeded")

    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        raise CanonicalJsonError("floating-point values are forbidden")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError("object keys must be strings")
            _validate_tree(
                child,
                depth=depth + 1,
                max_depth=max_depth,
                item_counter=item_counter,
                max_items=max_items,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_tree(
                child,
                depth=depth + 1,
                max_depth=max_depth,
                item_counter=item_counter,
                max_items=max_items,
            )
        return
    raise CanonicalJsonError(f"unsupported JSON value type: {type(value).__name__}")


def strict_json_loads(
    payload: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> Any:
    if isinstance(payload, bytes):
        if len(payload) > max_bytes:
            raise CanonicalJsonError("JSON byte limit exceeded")
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise CanonicalJsonError("JSON is not valid UTF-8") from error
    elif isinstance(payload, str):
        encoded = payload.encode("utf-8", errors="strict")
        if len(encoded) > max_bytes:
            raise CanonicalJsonError("JSON byte limit exceeded")
        text = payload
    else:
        raise CanonicalJsonError("JSON payload must be text or bytes")

    if text.startswith("\ufeff"):
        raise CanonicalJsonError("UTF-8 BOM is forbidden")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise CanonicalJsonError(f"invalid JSON: {error.msg}") from error

    _validate_tree(
        value,
        depth=0,
        max_depth=max_depth,
        item_counter=[0],
        max_items=max_items,
    )
    return value


def canonical_json_bytes(value: Any) -> bytes:
    _validate_tree(
        value,
        depth=0,
        max_depth=DEFAULT_MAX_DEPTH,
        item_counter=[0],
        max_items=DEFAULT_MAX_ITEMS,
    )
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
