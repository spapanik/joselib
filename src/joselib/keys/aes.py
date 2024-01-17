from __future__ import annotations

from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms, modes
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)
from cryptography.hazmat.primitives.padding import PKCS7

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWEError, JWKError
from joselib.keys.base import Key
from joselib.utils import base64url_encode, ensure_binary, get_random_bytes


class AESKey(Key):
    KEY_128 = (
        ALGORITHMS.A128GCM,
        ALGORITHMS.A128GCMKW,
        ALGORITHMS.A128KW,
        ALGORITHMS.A128CBC,
    )
    KEY_192 = (
        ALGORITHMS.A192GCM,
        ALGORITHMS.A192GCMKW,
        ALGORITHMS.A192KW,
        ALGORITHMS.A192CBC,
    )
    KEY_256 = (
        ALGORITHMS.A256GCM,
        ALGORITHMS.A256GCMKW,
        ALGORITHMS.A256KW,
        ALGORITHMS.A128CBC_HS256,
        ALGORITHMS.A256CBC,
    )
    KEY_384 = (ALGORITHMS.A192CBC_HS384,)
    KEY_512 = (ALGORITHMS.A256CBC_HS512,)

    AES_KW_ALGS = (ALGORITHMS.A128KW, ALGORITHMS.A192KW, ALGORITHMS.A256KW)

    MODES: ClassVar[dict[str, type[modes.Mode] | None]] = {
        ALGORITHMS.A128GCM: modes.GCM,
        ALGORITHMS.A192GCM: modes.GCM,
        ALGORITHMS.A256GCM: modes.GCM,
        ALGORITHMS.A128CBC_HS256: modes.CBC,
        ALGORITHMS.A192CBC_HS384: modes.CBC,
        ALGORITHMS.A256CBC_HS512: modes.CBC,
        ALGORITHMS.A128CBC: modes.CBC,
        ALGORITHMS.A192CBC: modes.CBC,
        ALGORITHMS.A256CBC: modes.CBC,
        ALGORITHMS.A128GCMKW: modes.GCM,
        ALGORITHMS.A192GCMKW: modes.GCM,
        ALGORITHMS.A256GCMKW: modes.GCM,
        ALGORITHMS.A128KW: None,
        ALGORITHMS.A192KW: None,
        ALGORITHMS.A256KW: None,
    }

    def __init__(self, key, algorithm: str):
        if algorithm not in ALGORITHMS.AES:
            msg = f"hash_alg: {algorithm} is not a valid AES algorithm"
            raise JWKError(msg)
        if algorithm not in ALGORITHMS.SUPPORTED.union(ALGORITHMS.AES_PSEUDO):
            msg = f"hash_alg: {algorithm} is not a supported algorithm"
            raise JWKError(msg)

        self._algorithm = algorithm
        self._mode = self.MODES.get(self._algorithm)

        if algorithm in self.KEY_128 and len(key) != 16:
            msg = f"Key must be 128 bit for alg {algorithm}"
            raise JWKError(msg)
        if algorithm in self.KEY_192 and len(key) != 24:
            msg = f"Key must be 192 bit for alg {algorithm}"
            raise JWKError(msg)
        if algorithm in self.KEY_256 and len(key) != 32:
            msg = f"Key must be 256 bit for alg {algorithm}"
            raise JWKError(msg)
        if algorithm in self.KEY_384 and len(key) != 48:
            msg = f"Key must be 384 bit for alg {algorithm}"
            raise JWKError(msg)
        if algorithm in self.KEY_512 and len(key) != 64:
            msg = f"Key must be 512 bit for alg {algorithm}"
            raise JWKError(msg)

        self._key = key

    def to_dict(self) -> dict[str, str | bytes]:
        return {"alg": self._algorithm, "kty": "oct", "k": base64url_encode(self._key)}

    def encrypt(self, plain_text: bytes, aad: bytes | None = None) -> bytes:
        plain_text = ensure_binary(plain_text)
        try:
            iv = get_random_bytes(algorithms.AES.block_size // 8)
            mode = self._mode(iv)
            if mode.name == "GCM":
                cipher = aead.AESGCM(self._key)
                cipher_text_and_tag = cipher.encrypt(iv, plain_text, aad)
                cipher_text = cipher_text_and_tag[: len(cipher_text_and_tag) - 16]
                auth_tag = cipher_text_and_tag[-16:]
            else:
                cipher = Cipher(
                    algorithms.AES(self._key), mode, backend=default_backend()
                )
                encryptor = cipher.encryptor()
                padder = PKCS7(algorithms.AES.block_size).padder()
                padded_data = padder.update(plain_text)
                padded_data += padder.finalize()
                cipher_text = encryptor.update(padded_data) + encryptor.finalize()
                auth_tag = None
        except Exception as err:
            raise JWEError(err) from err
        else:
            return iv, cipher_text, auth_tag

    def decrypt(
        self,
        cipher_text: bytes,
        iv: bytes | None = None,
        aad: bytes | None = None,
        tag: bytes | None = None,
    ) -> bytes:
        cipher_text = ensure_binary(cipher_text)
        try:
            iv = ensure_binary(iv)
            mode = self._mode(iv)
            if mode.name == "GCM":
                if tag is None:
                    msg = "tag cannot be None"
                    raise ValueError(msg)
                cipher = aead.AESGCM(self._key)
                cipher_text_and_tag = cipher_text + tag
                try:
                    plain_text = cipher.decrypt(iv, cipher_text_and_tag, aad)
                except InvalidTag as err:
                    msg = "Invalid JWE Auth Tag"
                    raise JWEError(msg) from err
            else:
                cipher = Cipher(
                    algorithms.AES(self._key), mode, backend=default_backend()
                )
                decryptor = cipher.decryptor()
                padded_plain_text = decryptor.update(cipher_text)
                padded_plain_text += decryptor.finalize()
                unpadder = PKCS7(algorithms.AES.block_size).unpadder()
                plain_text = unpadder.update(padded_plain_text)
                plain_text += unpadder.finalize()
        except Exception as err:
            raise JWEError(err) from err
        else:
            return plain_text

    def wrap_key(self, key_data: bytes) -> bytes:
        key_data = ensure_binary(key_data)
        return aes_key_wrap(self._key, key_data, default_backend())

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        wrapped_key = ensure_binary(wrapped_key)
        try:
            plain_text = aes_key_unwrap(self._key, wrapped_key, default_backend())
        except InvalidUnwrap as err:
            raise JWEError(err) from err
        return plain_text
