from __future__ import annotations

from typing import TYPE_CHECKING

from joselib.exceptions import JWEError, UnsupportedAlgorithmError
from joselib.jwa import CONTENT_ENCRYPTION_ALGORITHMS, KEY_MANAGEMENT_ALGORITHMS
from joselib.utils import b64url_decode, b64url_encode, json_decode, json_encode

if TYPE_CHECKING:
    from collections.abc import Mapping

    from joselib.jwk import Key

# "zip" is reserved because compressing plaintext before encryption leaks
# information about it and enables decompression bombs, so it is unsupported.
_RESERVED_HEADERS = frozenset({"alg", "crit", "enc", "zip"})
_SEGMENT_COUNT = 5


class JWE:
    __slots__ = ("_aad", "_encryption", "_header", "_key", "_key_management")

    def __init__(self, key: Key, algorithm: str, encryption: str) -> None:
        key_management = KEY_MANAGEMENT_ALGORITHMS.get(algorithm)
        if key_management is None:
            raise UnsupportedAlgorithmError(algorithm)
        content_encryption = CONTENT_ENCRYPTION_ALGORITHMS.get(encryption)
        if content_encryption is None:
            raise UnsupportedAlgorithmError(encryption)
        self._key = key
        self._key_management = key_management
        self._encryption = content_encryption
        header: dict[str, object] = {"alg": algorithm, "enc": encryption}
        if key.kid is not None:
            header["kid"] = key.kid
        self._header = header
        self._aad = b64url_encode(json_encode(header))

    def encrypt(
        self, plaintext: bytes, *, headers: Mapping[str, object] | None = None
    ) -> str:
        if headers:
            reserved = _RESERVED_HEADERS & headers.keys()
            if reserved:
                msg = f"headers {sorted(reserved)} are managed by the library"
                raise JWEError(msg)
            aad = b64url_encode(json_encode({**self._header, **headers}))
        else:
            aad = self._aad
        cek, encrypted_key = self._key_management.encrypt_cek(
            self._key, self._encryption
        )
        iv, ciphertext, tag = self._encryption.encrypt(cek, plaintext, aad)
        segments = (
            aad,
            b64url_encode(encrypted_key),
            b64url_encode(iv),
            b64url_encode(ciphertext),
            b64url_encode(tag),
        )
        return b".".join(segments).decode()

    def decrypt(self, token: str | bytes) -> bytes:
        if isinstance(token, str):
            token = token.encode()
        parts = token.split(b".")
        if len(parts) != _SEGMENT_COUNT:
            msg = "JWE token must have exactly five segments"
            raise JWEError(msg)
        header_segment, key_segment, iv_segment, text_segment, tag_segment = parts
        self._verify_header(json_decode(b64url_decode(header_segment)))
        cek = self._key_management.decrypt_cek(
            self._key, b64url_decode(key_segment), self._encryption
        )
        return self._encryption.decrypt(
            cek,
            b64url_decode(iv_segment),
            b64url_decode(text_segment),
            b64url_decode(tag_segment),
            header_segment,
        )

    def _verify_header(self, header: Mapping[str, object]) -> None:
        algorithm = header.get("alg")
        if algorithm != self._key_management.name:
            raise UnsupportedAlgorithmError(str(algorithm))
        encryption = header.get("enc")
        if encryption != self._encryption.name:
            raise UnsupportedAlgorithmError(str(encryption))
        if "zip" in header:
            msg = "compressed tokens are not supported"
            raise JWEError(msg)
        if "crit" in header:
            msg = "critical header parameters are not supported"
            raise JWEError(msg)
