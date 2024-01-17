from __future__ import annotations

import base64
import secrets
import struct
from datetime import timedelta

from cryptography.utils import int_to_bytes as _long_to_bytes

from joselib.types import HashFunction


def get_random_bytes(num_bytes: int) -> bytes:
    return secrets.token_bytes(num_bytes)


def long_to_bytes(n: int, blocksize: int = 0) -> bytes:
    return _long_to_bytes(n, blocksize or None)


def long_to_base64(data: int, size: int = 0) -> bytes:
    return base64.urlsafe_b64encode(long_to_bytes(data, size)).strip(b"=")


def int_arr_to_long(arr: tuple[int, ...]) -> int:
    return int("".join([f"{byte:02x}" for byte in arr]), 16)


def base64_to_long(data: str | int | bytes) -> int:
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b"==")
    return int_arr_to_long(struct.unpack(f"{len(_d)}B", _d))


def calculate_at_hash(access_token: str, hash_alg: HashFunction) -> str:
    """Helper method for calculating an access token
    hash, as described in http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

    Its value is the base64url encoding of the left-most half of the hash of the octets
    of the ASCII representation of the access_token value, where the hash algorithm
    used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE
    Header. For instance, if the alg is RS256, hash the access_token value with SHA-256,
    then take the left-most 128 bits and base64url encode them. The at_hash value is a
    case sensitive string.

    Args:
        access_token (str): An access token string.
        hash_alg (callable): A callable returning a hash object, e.g. hashlib.sha256

    """
    hash_digest = hash_alg(access_token.encode("utf-8")).digest()
    cut_at = len(hash_digest) // 2
    truncated = hash_digest[:cut_at]
    at_hash = base64url_encode(truncated)
    return at_hash.decode("utf-8")


def base64url_decode(encoded: bytes) -> bytes:
    """Helper method to base64url_decode a string.

    Args:
        input (str): A base64url_encoded string to decode.

    """
    rem = len(encoded) % 4

    if rem > 0:
        encoded += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(encoded)


def base64url_encode(unsafe_bytes: bytes) -> bytes:
    """Helper method to base64url_encode a string.

    Args:
        input (str): A base64url_encoded string to encode.

    """
    return base64.urlsafe_b64encode(unsafe_bytes).replace(b"=", b"")


def timedelta_total_seconds(delta: timedelta) -> int:
    """Helper method to determine the total number of seconds
    from a timedelta.

    Args:
        delta (timedelta): A timedelta to convert to seconds.
    """
    return delta.days * 24 * 60 * 60 + delta.seconds


def ensure_binary(s: str | bytes) -> bytes:
    """Coerce **s** to bytes."""

    if isinstance(s, bytes):
        return s
    if isinstance(s, str):
        return s.encode("utf-8", "strict")
    msg = f"not expecting type `{type(s)}`"  # type: ignore[unreachable]
    raise TypeError(msg)
