from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import ClassVar, TypeVar

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import (
    hashes,
    hmac,
    keywrap,
    padding as symmetric_padding,
)
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.constant_time import bytes_eq

from joselib.exceptions import DecryptionError, JWEError, JWKError
from joselib.jwk import ECKey, Key, OctKey, OKPKey, RSAKey

_HASH_TYPES: dict[int, type[hashes.HashAlgorithm]] = {
    256: hashes.SHA256,
    384: hashes.SHA384,
    512: hashes.SHA512,
}
_K = TypeVar("_K", bound=Key)


def _check_key(key: Key, expected: type[_K], algorithm: str) -> _K:
    if isinstance(key, expected):
        return key
    msg = f"{algorithm} requires {expected.__name__}, got {type(key).__name__}"
    raise JWKError(msg)


class SigningAlgorithm(ABC):
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def sign(self, key: Key, data: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, key: Key, data: bytes, signature: bytes) -> bool: ...


class HMACAlgorithm(SigningAlgorithm):
    __slots__ = ("_hash",)

    def __init__(self, size: int) -> None:
        super().__init__(f"HS{size}")
        self._hash = _HASH_TYPES[size]()

    def _secret(self, key: Key) -> bytes:
        secret = _check_key(key, OctKey, self.name).secret
        if len(secret) < self._hash.digest_size:
            msg = (
                f"{self.name} requires a key of at least {self._hash.digest_size} bytes"
            )
            raise JWKError(msg)
        return secret

    def sign(self, key: Key, data: bytes) -> bytes:
        mac = hmac.HMAC(self._secret(key), self._hash)
        mac.update(data)
        return mac.finalize()

    def verify(self, key: Key, data: bytes, signature: bytes) -> bool:
        return bytes_eq(self.sign(key, data), signature)


class RSAAlgorithm(SigningAlgorithm):
    __slots__ = ("_hash", "_padding")

    def __init__(self, size: int, *, pss: bool) -> None:
        super().__init__(f"PS{size}" if pss else f"RS{size}")
        self._hash = _HASH_TYPES[size]()
        if pss:
            self._padding: padding.AsymmetricPadding = padding.PSS(
                mgf=padding.MGF1(self._hash), salt_length=self._hash.digest_size
            )
        else:
            self._padding = padding.PKCS1v15()

    def sign(self, key: Key, data: bytes) -> bytes:
        rsa_key = _check_key(key, RSAKey, self.name)
        return rsa_key.crypto_private_key.sign(data, self._padding, self._hash)

    def verify(self, key: Key, data: bytes, signature: bytes) -> bool:
        rsa_key = _check_key(key, RSAKey, self.name)
        try:
            rsa_key.crypto_public_key.verify(signature, data, self._padding, self._hash)
        except InvalidSignature:
            return False
        return True


class ECAlgorithm(SigningAlgorithm):
    __slots__ = ("_curve", "_hash")

    def __init__(self, size: int, curve: str) -> None:
        super().__init__(f"ES{size}")
        self._hash = _HASH_TYPES[size]()
        self._curve = curve

    def _check_curve(self, key: Key) -> ECKey:
        ec_key = _check_key(key, ECKey, self.name)
        if ec_key.curve != self._curve:
            msg = f"{self.name} requires a {self._curve} key, got {ec_key.curve}"
            raise JWKError(msg)
        return ec_key

    @staticmethod
    def _coordinate_size(key: ECKey) -> int:
        return (key.crypto_public_key.curve.key_size + 7) // 8

    def sign(self, key: Key, data: bytes) -> bytes:
        ec_key = self._check_curve(key)
        der = ec_key.crypto_private_key.sign(data, ec.ECDSA(self._hash))
        r, s = decode_dss_signature(der)
        size = self._coordinate_size(ec_key)
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    def verify(self, key: Key, data: bytes, signature: bytes) -> bool:
        ec_key = self._check_curve(key)
        size = self._coordinate_size(ec_key)
        if len(signature) != 2 * size:
            return False
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        try:
            ec_key.crypto_public_key.verify(
                encode_dss_signature(r, s), data, ec.ECDSA(self._hash)
            )
        except (InvalidSignature, ValueError):
            return False
        return True


class EdDSAAlgorithm(SigningAlgorithm):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("EdDSA")

    def sign(self, key: Key, data: bytes) -> bytes:
        okp_key = _check_key(key, OKPKey, self.name)
        return okp_key.crypto_private_key.sign(data)

    def verify(self, key: Key, data: bytes, signature: bytes) -> bool:
        okp_key = _check_key(key, OKPKey, self.name)
        try:
            okp_key.crypto_public_key.verify(signature, data)
        except InvalidSignature:
            return False
        return True


class ContentEncryptionAlgorithm(ABC):
    __slots__ = ("key_size", "name")
    iv_size: ClassVar[int]

    def __init__(self, name: str, key_size: int) -> None:
        self.name = name
        self.key_size = key_size

    def generate_cek(self) -> bytes:
        return os.urandom(self.key_size)

    def _check_cek(self, cek: bytes) -> None:
        if len(cek) != self.key_size:
            msg = f"{self.name} requires a {self.key_size}-byte content key"
            raise JWEError(msg)

    @abstractmethod
    def encrypt(
        self, cek: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt the plaintext and return (iv, ciphertext, tag)."""

    @abstractmethod
    def decrypt(
        self, cek: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        """Authenticate and decrypt the ciphertext."""


class GCMEncryption(ContentEncryptionAlgorithm):
    __slots__ = ()
    iv_size: ClassVar[int] = 12
    tag_size: ClassVar[int] = 16

    def __init__(self, size: int) -> None:
        super().__init__(f"A{size}GCM", size // 8)

    def encrypt(
        self, cek: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes, bytes]:
        self._check_cek(cek)
        iv = os.urandom(self.iv_size)
        sealed = AESGCM(cek).encrypt(iv, plaintext, aad)
        return iv, sealed[: -self.tag_size], sealed[-self.tag_size :]

    def decrypt(
        self, cek: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        if (
            len(cek) != self.key_size
            or len(iv) != self.iv_size
            or len(tag) != self.tag_size
        ):
            raise DecryptionError
        try:
            return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
        except InvalidTag as exc:
            raise DecryptionError from exc


class CBCHMACEncryption(ContentEncryptionAlgorithm):
    __slots__ = ("_half", "_hash")
    iv_size: ClassVar[int] = 16

    def __init__(self, size: int) -> None:
        super().__init__(f"A{size}CBC-HS{size * 2}", size // 4)
        self._hash = _HASH_TYPES[size * 2]()
        self._half = size // 8

    def _tag(self, mac_key: bytes, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        mac = hmac.HMAC(mac_key, self._hash)
        mac.update(aad)
        mac.update(iv)
        mac.update(ciphertext)
        mac.update((len(aad) * 8).to_bytes(8, "big"))
        return mac.finalize()[: self._half]

    def encrypt(
        self, cek: bytes, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes, bytes]:
        self._check_cek(cek)
        mac_key, enc_key = cek[: self._half], cek[self._half :]
        iv = os.urandom(self.iv_size)
        padder = symmetric_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return iv, ciphertext, self._tag(mac_key, iv, ciphertext, aad)

    def decrypt(
        self, cek: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        if (
            len(cek) != self.key_size
            or len(iv) != self.iv_size
            or len(ciphertext) % 16 != 0
            or not ciphertext
        ):
            raise DecryptionError
        mac_key, enc_key = cek[: self._half], cek[self._half :]
        if not bytes_eq(self._tag(mac_key, iv, ciphertext, aad), tag):
            raise DecryptionError
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise DecryptionError from exc


class KeyManagementAlgorithm(ABC):
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def encrypt_cek(
        self, key: Key, enc: ContentEncryptionAlgorithm
    ) -> tuple[bytes, bytes]:
        """Return (cek, encrypted_key) for a new token."""

    @abstractmethod
    def decrypt_cek(
        self, key: Key, encrypted_key: bytes, enc: ContentEncryptionAlgorithm
    ) -> bytes:
        """Recover the cek from the encrypted key of a token."""


class DirectAlgorithm(KeyManagementAlgorithm):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("dir")

    def _secret(self, key: Key, enc: ContentEncryptionAlgorithm) -> bytes:
        secret = _check_key(key, OctKey, self.name).secret
        if len(secret) != enc.key_size:
            msg = f"dir with {enc.name} requires a {enc.key_size}-byte key"
            raise JWKError(msg)
        return secret

    def encrypt_cek(
        self, key: Key, enc: ContentEncryptionAlgorithm
    ) -> tuple[bytes, bytes]:
        return self._secret(key, enc), b""

    def decrypt_cek(
        self, key: Key, encrypted_key: bytes, enc: ContentEncryptionAlgorithm
    ) -> bytes:
        secret = self._secret(key, enc)
        if encrypted_key:
            raise DecryptionError
        return secret


class AESKWAlgorithm(KeyManagementAlgorithm):
    __slots__ = ("_size",)

    def __init__(self, size: int) -> None:
        super().__init__(f"A{size}KW")
        self._size = size // 8

    def _secret(self, key: Key) -> bytes:
        secret = _check_key(key, OctKey, self.name).secret
        if len(secret) != self._size:
            msg = f"{self.name} requires a {self._size}-byte key"
            raise JWKError(msg)
        return secret

    def encrypt_cek(
        self, key: Key, enc: ContentEncryptionAlgorithm
    ) -> tuple[bytes, bytes]:
        cek = enc.generate_cek()
        return cek, keywrap.aes_key_wrap(self._secret(key), cek)

    def decrypt_cek(
        self, key: Key, encrypted_key: bytes, enc: ContentEncryptionAlgorithm
    ) -> bytes:
        secret = self._secret(key)
        try:
            cek = keywrap.aes_key_unwrap(secret, encrypted_key)
        except (keywrap.InvalidUnwrap, ValueError) as exc:
            raise DecryptionError from exc
        if len(cek) != enc.key_size:
            raise DecryptionError
        return cek


class RSAOAEPAlgorithm(KeyManagementAlgorithm):
    __slots__ = ("_padding",)

    def __init__(self, *, sha256: bool) -> None:
        super().__init__("RSA-OAEP-256" if sha256 else "RSA-OAEP")
        hash_type: type[hashes.HashAlgorithm] = hashes.SHA256 if sha256 else hashes.SHA1
        self._padding = padding.OAEP(
            mgf=padding.MGF1(hash_type()), algorithm=hash_type(), label=None
        )

    def encrypt_cek(
        self, key: Key, enc: ContentEncryptionAlgorithm
    ) -> tuple[bytes, bytes]:
        rsa_key = _check_key(key, RSAKey, self.name)
        cek = enc.generate_cek()
        return cek, rsa_key.crypto_public_key.encrypt(cek, self._padding)

    def decrypt_cek(
        self, key: Key, encrypted_key: bytes, enc: ContentEncryptionAlgorithm
    ) -> bytes:
        rsa_key = _check_key(key, RSAKey, self.name)
        try:
            cek = rsa_key.crypto_private_key.decrypt(encrypted_key, self._padding)
        except ValueError as exc:
            raise DecryptionError from exc
        if len(cek) != enc.key_size:
            raise DecryptionError
        return cek


SIGNING_ALGORITHMS: dict[str, SigningAlgorithm] = {
    algorithm.name: algorithm
    for algorithm in (
        HMACAlgorithm(256),
        HMACAlgorithm(384),
        HMACAlgorithm(512),
        RSAAlgorithm(256, pss=False),
        RSAAlgorithm(384, pss=False),
        RSAAlgorithm(512, pss=False),
        RSAAlgorithm(256, pss=True),
        RSAAlgorithm(384, pss=True),
        RSAAlgorithm(512, pss=True),
        ECAlgorithm(256, "P-256"),
        ECAlgorithm(384, "P-384"),
        ECAlgorithm(512, "P-521"),
        EdDSAAlgorithm(),
    )
}
KEY_MANAGEMENT_ALGORITHMS: dict[str, KeyManagementAlgorithm] = {
    algorithm.name: algorithm
    for algorithm in (
        DirectAlgorithm(),
        AESKWAlgorithm(128),
        AESKWAlgorithm(192),
        AESKWAlgorithm(256),
        RSAOAEPAlgorithm(sha256=False),
        RSAOAEPAlgorithm(sha256=True),
    )
}
CONTENT_ENCRYPTION_ALGORITHMS: dict[str, ContentEncryptionAlgorithm] = {
    algorithm.name: algorithm
    for algorithm in (
        CBCHMACEncryption(128),
        CBCHMACEncryption(192),
        CBCHMACEncryption(256),
        GCMEncryption(128),
        GCMEncryption(192),
        GCMEncryption(256),
    )
}
