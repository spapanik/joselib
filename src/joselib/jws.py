from __future__ import annotations

from typing import TYPE_CHECKING

from joselib.exceptions import (
    InvalidSignatureError,
    JWSError,
    UnsupportedAlgorithmError,
)
from joselib.jwa import SIGNING_ALGORITHMS
from joselib.utils import b64url_decode, b64url_encode, json_decode, json_encode

if TYPE_CHECKING:
    from collections.abc import Mapping, Set as AbstractSet

    from joselib.jwa import SigningAlgorithm
    from joselib.jwk import Key

_RESERVED_HEADERS = frozenset({"alg", "crit"})
_SEGMENT_COUNT = 3


def _merge_headers(
    base: Mapping[str, object], extra: Mapping[str, object]
) -> dict[str, object]:
    reserved = _RESERVED_HEADERS & extra.keys()
    if reserved:
        msg = f"headers {sorted(reserved)} are managed by the library"
        raise JWSError(msg)
    return {**base, **extra}


class JWS:
    __slots__ = ("_algorithm", "_allowed", "_header", "_key", "_prefix")

    def __init__(
        self,
        key: Key,
        algorithm: str,
        *,
        allowed_algorithms: AbstractSet[str] | None = None,
        headers: Mapping[str, object] | None = None,
    ) -> None:
        implementation = SIGNING_ALGORITHMS.get(algorithm)
        if implementation is None:
            raise UnsupportedAlgorithmError(algorithm)
        allowed = (
            frozenset(allowed_algorithms)
            if allowed_algorithms is not None
            else frozenset((algorithm,))
        )
        for name in allowed:
            if name not in SIGNING_ALGORITHMS:
                raise UnsupportedAlgorithmError(name)
        self._key = key
        self._algorithm = implementation
        self._allowed = allowed
        header: dict[str, object] = {"alg": algorithm}
        if key.kid is not None:
            header["kid"] = key.kid
        if headers is not None:
            header = _merge_headers(header, headers)
        self._header = header
        self._prefix = b64url_encode(json_encode(header)) + b"."

    def sign(
        self, payload: bytes, *, headers: Mapping[str, object] | None = None
    ) -> str:
        if headers:
            header = _merge_headers(self._header, headers)
            prefix = b64url_encode(json_encode(header)) + b"."
        else:
            prefix = self._prefix
        signing_input = prefix + b64url_encode(payload)
        signature = self._algorithm.sign(self._key, signing_input)
        return (signing_input + b"." + b64url_encode(signature)).decode()

    def verify(self, token: str | bytes) -> bytes:
        if isinstance(token, str):
            token = token.encode()
        parts = token.split(b".")
        if len(parts) != _SEGMENT_COUNT:
            msg = "JWS token must have exactly three segments"
            raise JWSError(msg)
        header_segment, payload_segment, signature_segment = parts
        header = json_decode(b64url_decode(header_segment))
        algorithm = self._verify_header(header)
        signature = b64url_decode(signature_segment)
        signing_input = header_segment + b"." + payload_segment
        if not algorithm.verify(self._key, signing_input, signature):
            raise InvalidSignatureError
        return b64url_decode(payload_segment)

    def _verify_header(self, header: Mapping[str, object]) -> SigningAlgorithm:
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in self._allowed:
            raise UnsupportedAlgorithmError(str(algorithm))
        if "crit" in header:
            msg = "critical header parameters are not supported"
            raise JWSError(msg)
        return SIGNING_ALGORITHMS[algorithm]

    @staticmethod
    def unverified_header(token: str | bytes) -> dict[str, object]:
        """Parse the protected header WITHOUT verifying the token.

        The returned values are unauthenticated: never trust them for
        anything other than selecting a verification key.
        """
        if isinstance(token, str):
            token = token.encode()
        return json_decode(b64url_decode(token.split(b".", 1)[0]))
