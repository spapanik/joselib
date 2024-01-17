from __future__ import annotations

from typing import ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWKError
from joselib.keys.base import Key
from joselib.utils import base64url_decode, base64url_encode, ensure_binary


class HMACKey(Key):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """

    ALG_MAP: ClassVar[dict[str, hashes.HashAlgorithm]] = {
        ALGORITHMS.HS256: hashes.SHA256(),
        ALGORITHMS.HS384: hashes.SHA384(),
        ALGORITHMS.HS512: hashes.SHA512(),
    }

    def __init__(self, key, algorithm: str):
        if algorithm not in ALGORITHMS.HMAC:
            msg = f"hash_alg: {algorithm} is not a valid hash algorithm"
            raise JWKError(msg)
        self._algorithm = algorithm
        self._hash_alg = self.ALG_MAP.get(algorithm)

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if not isinstance(key, str) and not isinstance(key, bytes):
            msg = "Expecting a string- or bytes-formatted key."
            raise JWKError(msg)

        if isinstance(key, str):
            key = key.encode("utf-8")

        invalid_strings = [
            b"-----BEGIN PUBLIC KEY-----",
            b"-----BEGIN RSA PUBLIC KEY-----",
            b"-----BEGIN CERTIFICATE-----",
            b"ssh-rsa",
        ]

        if any(string_value in key for string_value in invalid_strings):
            msg = "The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret."
            raise JWKError(msg)

        self.prepared_key = key

    def _process_jwk(self, jwk_dict: dict[str, str]) -> bytes:
        if jwk_dict.get("kty") != "oct":
            kty = jwk_dict.get("kty")
            msg = f"Incorrect key type. Expected: `oct`, Received: {kty}"
            raise JWKError(msg)

        k = jwk_dict.get("k")
        k = k.encode("utf-8")
        k = bytes(k)
        return base64url_decode(k)

    def to_dict(self) -> dict[str, str | bytes]:
        return {
            "alg": self._algorithm,
            "kty": "oct",
            "k": base64url_encode(self.prepared_key).decode("ASCII"),
        }

    def sign(self, msg: bytes) -> bytes:
        msg = ensure_binary(msg)
        h = hmac.HMAC(self.prepared_key, self._hash_alg, backend=default_backend())
        h.update(msg)
        return h.finalize()

    def verify(self, msg: bytes, sig: bytes) -> bool:
        msg = ensure_binary(msg)
        sig = ensure_binary(sig)
        h = hmac.HMAC(self.prepared_key, self._hash_alg, backend=default_backend())
        h.update(msg)
        try:
            h.verify(sig)
        except InvalidSignature:
            return False
        return True
