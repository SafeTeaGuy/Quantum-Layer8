"""Canonical JSON and digests for the quantum branch prototype.

Floats are refused. A float has no single canonical text form across
languages, so a signed body that contains one could verify in one
implementation and not another. Numeric workload parameters are carried as
decimal strings and costs as integer micro-USD.
"""

import hashlib
import json
import re
from typing import Any

MAX_DEPTH = 32
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}\Z")


class CanonicalError(ValueError):
    pass


def _check(obj: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("nesting too deep")
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, int):
        return
    if isinstance(obj, float):
        raise CanonicalError("floats are not canonical; use a decimal string")
    if isinstance(obj, list):
        for v in obj:
            _check(v, depth + 1)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalError("object keys must be strings")
            _check(v, depth + 1)
        return
    raise CanonicalError(f"unsupported type {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def domain_separated(domain: str, obj: Any) -> bytes:
    """len(domain) || domain || canonical(obj), the core Layer8 construction."""
    if not isinstance(domain, str) or not _DOMAIN_RE.match(domain):
        raise CanonicalError("malformed domain")
    d = domain.encode("ascii")
    return bytes([len(d)]) + d + canonical_bytes(obj)


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)
