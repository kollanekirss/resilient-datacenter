"""Bounded JSON contracts. Error messages never interpolate input values."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

Json = dict[str, Any]
SitePlan = ReleaseLock = Inventory = Evidence = VmSpec = Json


class ApplianceError(ValueError):
    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ApplianceError(code)


def fields(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    require(type(value) is dict, "object-required")
    require(not set(value) - required - optional, "unknown-field")
    require(required <= set(value), "missing-field")


def integer(value: Any, minimum: int, maximum: int) -> int:
    require(type(value) is int and minimum <= value <= maximum, "invalid-integer")
    return value


def _no_floats(value: Any, depth: int = 0) -> None:
    require(depth <= 32, "json-depth")
    require(type(value) in (dict, list, str, int, bool, type(None)), "json-value")
    if isinstance(value, dict):
        require(all(type(k) is str for k in value), "json-key")
        for item in value.values():
            _no_floats(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _no_floats(item, depth + 1)


def canonical(record: Json) -> bytes:
    try:
        _no_floats(record)
        return json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, UnicodeError, RecursionError) as error:
        raise ApplianceError("invalid-json") from None


def identity(record: Json) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def load_json(path: Path, *, limit: int = 1024 * 1024) -> Json:
    """Read a non-symlink regular file with a strict byte and nesting limit."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode), "regular-file-required")
            require(info.st_size <= limit, "json-size")
            raw = source.read(limit + 1)
        require(len(raw) <= limit, "json-size")
        result = json.loads(raw, object_pairs_hook=_unique)
        require(type(result) is dict, "object-required")
        _no_floats(result)
        return result
    except ApplianceError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ApplianceError("invalid-json-file") from None
