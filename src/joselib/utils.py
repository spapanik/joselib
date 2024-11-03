from __future__ import annotations

import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import TYPE_CHECKING, cast

from joselib.exceptions import DecodeError

if TYPE_CHECKING:
    from collections.abc import Mapping

_B64URL_RE = re.compile(rb"[A-Za-z0-9_-]*\Z")
# Base64url encodings whose final character carries non-zero unused bits are
# malleable: they decode to the same bytes as the canonical form.  The final
# character of a valid encoding is restricted per RFC 4648 section 3.5.
_VALID_LAST_CHAR = {
    2: frozenset(b"AQgw"),
    3: frozenset(b"AEIMQUYcgkosw048"),
}


def b64url_encode(data: bytes) -> bytes:
    return urlsafe_b64encode(data).rstrip(b"=")


def b64url_decode(data: bytes) -> bytes:
    if _B64URL_RE.fullmatch(data) is None:
        msg = "invalid base64url characters"
        raise DecodeError(msg)
    remainder = len(data) % 4
    if remainder == 1:
        msg = "invalid base64url length"
        raise DecodeError(msg)
    if remainder and data[-1] not in _VALID_LAST_CHAR[remainder]:
        msg = "non-canonical base64url encoding"
        raise DecodeError(msg)
    return urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for key, value in pairs:
        if key in mapping:
            msg = f"duplicate JSON key: {key!r}"
            raise DecodeError(msg)
        mapping[key] = value
    return mapping


def json_decode(data: bytes) -> dict[str, object]:
    try:
        decoded: object = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:
        msg = "invalid JSON"
        raise DecodeError(msg) from exc
    if not isinstance(decoded, dict):
        msg = "JSON value is not an object"
        raise DecodeError(msg)
    return cast("dict[str, object]", decoded)


def json_encode(obj: Mapping[str, object]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
