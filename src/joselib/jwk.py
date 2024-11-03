from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hashes import SHA256, Hash

from joselib.exceptions import DecodeError, JWKError
from joselib.utils import b64url_decode, b64url_encode, json_decode, json_encode

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import (
        Self,  # upgrade: py3.10: use typing module
        TypeAlias,
    )

    _EdPrivateKey: TypeAlias = ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey
    _EdPublicKey: TypeAlias = ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
    _PrivateKey: TypeAlias = (
        rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | _EdPrivateKey
    )
    _PublicKey: TypeAlias = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | _EdPublicKey

_EC_CURVE_TYPES: dict[str, type[ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}
_EC_CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
_OKP_PRIVATE_TYPES: dict[str, type[_EdPrivateKey]] = {
    "Ed25519": ed25519.Ed25519PrivateKey,
    "Ed448": ed448.Ed448PrivateKey,
}
_OKP_PUBLIC_TYPES: dict[str, type[_EdPublicKey]] = {
    "Ed25519": ed25519.Ed25519PublicKey,
    "Ed448": ed448.Ed448PublicKey,
}


def _require_str(jwk: Mapping[str, object], field: str) -> str:
    value = jwk.get(field)
    if not isinstance(value, str):
        msg = f"missing or invalid JWK field: {field!r}"
        raise JWKError(msg)
    return value


def _optional_str(jwk: Mapping[str, object], field: str) -> str | None:
    value = jwk.get(field)
    if value is not None and not isinstance(value, str):
        msg = f"invalid JWK field: {field!r}"
        raise JWKError(msg)
    return value


def _b64_to_int(value: str) -> int:
    return int.from_bytes(b64url_decode(value.encode()), "big")


def _int_to_b64(value: int, size: int | None = None) -> str:
    if size is None:
        size = (value.bit_length() + 7) // 8 or 1
    return b64url_encode(value.to_bytes(size, "big")).decode()


def _pem_private(key: _PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _pem_public(key: _PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class Key(ABC):
    kty: ClassVar[str]
    __slots__ = ("_kid",)

    def __init__(self, kid: str | None = None) -> None:
        self._kid = kid

    @property
    def kid(self) -> str | None:
        return self._kid

    @property
    @abstractmethod
    def is_private(self) -> bool: ...

    @abstractmethod
    def public(self) -> Key:
        """Return a copy of this key without any private material."""

    @abstractmethod
    def to_jwk(self, *, private: bool = False) -> dict[str, str]:
        """Export the key as a JWK dict."""

    @abstractmethod
    def _thumbprint_fields(self) -> dict[str, str]: ...

    def thumbprint(self) -> str:
        digest = Hash(SHA256())
        digest.update(json_encode(self._thumbprint_fields()))
        return b64url_encode(digest.finalize()).decode()

    @classmethod
    def from_jwk(cls, jwk: Mapping[str, object] | str | bytes) -> Self:
        if isinstance(jwk, str):
            jwk = jwk.encode()
        if isinstance(jwk, bytes):
            jwk = json_decode(jwk)
        kty = jwk.get("kty")
        loader = _JWK_LOADERS.get(kty) if isinstance(kty, str) else None
        if loader is None:
            msg = f"unsupported JWK key type: {kty!r}"
            raise JWKError(msg)
        try:
            key = loader(jwk)
        except (ValueError, DecodeError) as exc:
            msg = "invalid JWK parameters"
            raise JWKError(msg) from exc
        if not isinstance(key, cls):
            msg = f"JWK key type {kty!r} does not match {cls.__name__}"
            raise JWKError(msg)
        return key

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> Self:
        loaded: _PrivateKey | _PublicKey
        try:
            loaded = _load_pem(pem, password)
        except (ValueError, TypeError) as exc:
            msg = "could not load PEM key"
            raise JWKError(msg) from exc
        key = _from_crypto_key(loaded)
        if not isinstance(key, cls):
            msg = f"PEM key type does not match {cls.__name__}"
            raise JWKError(msg)
        return key


class OctKey(Key):
    kty: ClassVar[str] = "oct"
    __slots__ = ("_secret",)
    MIN_SIZE: ClassVar[int] = 16

    def __init__(self, secret: bytes, kid: str | None = None) -> None:
        if len(secret) < self.MIN_SIZE:
            msg = f"oct keys must be at least {self.MIN_SIZE} bytes long"
            raise JWKError(msg)
        super().__init__(kid)
        self._secret = secret

    @classmethod
    def generate(cls, size: int = 32) -> Self:
        return cls(secrets.token_bytes(size))

    @property
    def secret(self) -> bytes:
        return self._secret

    @property
    def is_private(self) -> bool:
        return True

    def public(self) -> Key:
        msg = "symmetric keys have no public part"
        raise JWKError(msg)

    def to_jwk(self, *, private: bool = False) -> dict[str, str]:
        if not private:
            msg = "symmetric keys can only be exported with private=True"
            raise JWKError(msg)
        jwk = {"kty": self.kty, "k": b64url_encode(self._secret).decode()}
        if self.kid is not None:
            jwk["kid"] = self.kid
        return jwk

    def _thumbprint_fields(self) -> dict[str, str]:
        return {"kty": self.kty, "k": b64url_encode(self._secret).decode()}


class RSAKey(Key):
    kty: ClassVar[str] = "RSA"
    __slots__ = ("_private_key", "_public_key")
    MIN_SIZE: ClassVar[int] = 2048

    def __init__(
        self, key: rsa.RSAPrivateKey | rsa.RSAPublicKey, kid: str | None = None
    ) -> None:
        super().__init__(kid)
        if isinstance(key, rsa.RSAPrivateKey):
            self._private_key: rsa.RSAPrivateKey | None = key
            self._public_key = key.public_key()
        else:
            self._private_key = None
            self._public_key = key
        if self._public_key.key_size < self.MIN_SIZE:
            msg = f"RSA keys must be at least {self.MIN_SIZE} bits long"
            raise JWKError(msg)

    @classmethod
    def generate(cls, size: int = 2048) -> Self:
        if size < cls.MIN_SIZE:
            msg = f"RSA keys must be at least {cls.MIN_SIZE} bits long"
            raise JWKError(msg)
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=size))

    @property
    def crypto_private_key(self) -> rsa.RSAPrivateKey:
        if self._private_key is None:
            msg = "key has no private part"
            raise JWKError(msg)
        return self._private_key

    @property
    def crypto_public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    @property
    def is_private(self) -> bool:
        return self._private_key is not None

    def public(self) -> RSAKey:
        if self._private_key is None:
            return self
        return RSAKey(self._public_key, kid=self.kid)

    def to_jwk(self, *, private: bool = False) -> dict[str, str]:
        public_numbers = self._public_key.public_numbers()
        jwk = {
            "kty": self.kty,
            "n": _int_to_b64(public_numbers.n),
            "e": _int_to_b64(public_numbers.e),
        }
        if private:
            numbers = self.crypto_private_key.private_numbers()
            jwk["d"] = _int_to_b64(numbers.d)
            jwk["p"] = _int_to_b64(numbers.p)
            jwk["q"] = _int_to_b64(numbers.q)
            jwk["dp"] = _int_to_b64(numbers.dmp1)
            jwk["dq"] = _int_to_b64(numbers.dmq1)
            jwk["qi"] = _int_to_b64(numbers.iqmp)
        if self.kid is not None:
            jwk["kid"] = self.kid
        return jwk

    def to_pem(self, *, private: bool = False) -> bytes:
        if private:
            return _pem_private(self.crypto_private_key)
        return _pem_public(self._public_key)

    def _thumbprint_fields(self) -> dict[str, str]:
        public_numbers = self._public_key.public_numbers()
        return {
            "kty": self.kty,
            "n": _int_to_b64(public_numbers.n),
            "e": _int_to_b64(public_numbers.e),
        }


class ECKey(Key):
    kty: ClassVar[str] = "EC"
    __slots__ = ("_curve", "_private_key", "_public_key")

    def __init__(
        self,
        key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey,
        kid: str | None = None,
    ) -> None:
        super().__init__(kid)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            self._private_key: ec.EllipticCurvePrivateKey | None = key
            self._public_key = key.public_key()
        else:
            self._private_key = None
            self._public_key = key
        curve = _EC_CURVE_NAMES.get(self._public_key.curve.name)
        if curve is None:
            msg = f"unsupported EC curve: {self._public_key.curve.name!r}"
            raise JWKError(msg)
        self._curve = curve

    @classmethod
    def generate(cls, curve: str = "P-256") -> Self:
        curve_type = _EC_CURVE_TYPES.get(curve)
        if curve_type is None:
            msg = f"unsupported EC curve: {curve!r}"
            raise JWKError(msg)
        return cls(ec.generate_private_key(curve_type()))

    @property
    def curve(self) -> str:
        return self._curve

    @property
    def crypto_private_key(self) -> ec.EllipticCurvePrivateKey:
        if self._private_key is None:
            msg = "key has no private part"
            raise JWKError(msg)
        return self._private_key

    @property
    def crypto_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    @property
    def is_private(self) -> bool:
        return self._private_key is not None

    def public(self) -> ECKey:
        if self._private_key is None:
            return self
        return ECKey(self._public_key, kid=self.kid)

    @property
    def _coordinate_size(self) -> int:
        return (self._public_key.curve.key_size + 7) // 8

    def to_jwk(self, *, private: bool = False) -> dict[str, str]:
        size = self._coordinate_size
        public_numbers = self._public_key.public_numbers()
        jwk = {
            "kty": self.kty,
            "crv": self._curve,
            "x": _int_to_b64(public_numbers.x, size),
            "y": _int_to_b64(public_numbers.y, size),
        }
        if private:
            numbers = self.crypto_private_key.private_numbers()
            jwk["d"] = _int_to_b64(numbers.private_value, size)
        if self.kid is not None:
            jwk["kid"] = self.kid
        return jwk

    def to_pem(self, *, private: bool = False) -> bytes:
        if private:
            return _pem_private(self.crypto_private_key)
        return _pem_public(self._public_key)

    def _thumbprint_fields(self) -> dict[str, str]:
        size = self._coordinate_size
        public_numbers = self._public_key.public_numbers()
        return {
            "kty": self.kty,
            "crv": self._curve,
            "x": _int_to_b64(public_numbers.x, size),
            "y": _int_to_b64(public_numbers.y, size),
        }


class OKPKey(Key):
    kty: ClassVar[str] = "OKP"
    __slots__ = ("_curve", "_private_key", "_public_key")

    def __init__(
        self, key: _EdPrivateKey | _EdPublicKey, kid: str | None = None
    ) -> None:
        super().__init__(kid)
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            self._private_key: _EdPrivateKey | None = key
            self._public_key: _EdPublicKey = key.public_key()
        else:
            self._private_key = None
            self._public_key = key
        if isinstance(self._public_key, ed25519.Ed25519PublicKey):
            self._curve = "Ed25519"
        else:
            self._curve = "Ed448"

    @classmethod
    def generate(cls, curve: str = "Ed25519") -> Self:
        private_type = _OKP_PRIVATE_TYPES.get(curve)
        if private_type is None:
            msg = f"unsupported OKP curve: {curve!r}"
            raise JWKError(msg)
        return cls(private_type.generate())

    @property
    def curve(self) -> str:
        return self._curve

    @property
    def crypto_private_key(self) -> _EdPrivateKey:
        if self._private_key is None:
            msg = "key has no private part"
            raise JWKError(msg)
        return self._private_key

    @property
    def crypto_public_key(self) -> _EdPublicKey:
        return self._public_key

    @property
    def is_private(self) -> bool:
        return self._private_key is not None

    def public(self) -> OKPKey:
        if self._private_key is None:
            return self
        return OKPKey(self._public_key, kid=self.kid)

    def to_jwk(self, *, private: bool = False) -> dict[str, str]:
        jwk = {
            "kty": self.kty,
            "crv": self._curve,
            "x": b64url_encode(self._public_key.public_bytes_raw()).decode(),
        }
        if private:
            secret = self.crypto_private_key.private_bytes_raw()
            jwk["d"] = b64url_encode(secret).decode()
        if self.kid is not None:
            jwk["kid"] = self.kid
        return jwk

    def to_pem(self, *, private: bool = False) -> bytes:
        if private:
            return _pem_private(self.crypto_private_key)
        return _pem_public(self._public_key)

    def _thumbprint_fields(self) -> dict[str, str]:
        return {
            "kty": self.kty,
            "crv": self._curve,
            "x": b64url_encode(self._public_key.public_bytes_raw()).decode(),
        }


def _load_oct(jwk: Mapping[str, object]) -> OctKey:
    secret = b64url_decode(_require_str(jwk, "k").encode())
    return OctKey(secret, kid=_optional_str(jwk, "kid"))


def _load_rsa(jwk: Mapping[str, object]) -> RSAKey:
    public_numbers = rsa.RSAPublicNumbers(
        e=_b64_to_int(_require_str(jwk, "e")), n=_b64_to_int(_require_str(jwk, "n"))
    )
    kid = _optional_str(jwk, "kid")
    d_raw = _optional_str(jwk, "d")
    if d_raw is None:
        return RSAKey(public_numbers.public_key(), kid=kid)
    d = _b64_to_int(d_raw)
    p_raw = _optional_str(jwk, "p")
    q_raw = _optional_str(jwk, "q")
    if p_raw is None or q_raw is None:
        p, q = rsa.rsa_recover_prime_factors(public_numbers.n, public_numbers.e, d)
    else:
        p, q = _b64_to_int(p_raw), _b64_to_int(q_raw)
    dp_raw = _optional_str(jwk, "dp")
    dq_raw = _optional_str(jwk, "dq")
    qi_raw = _optional_str(jwk, "qi")
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=_b64_to_int(dp_raw) if dp_raw is not None else rsa.rsa_crt_dmp1(d, p),
        dmq1=_b64_to_int(dq_raw) if dq_raw is not None else rsa.rsa_crt_dmq1(d, q),
        iqmp=_b64_to_int(qi_raw) if qi_raw is not None else rsa.rsa_crt_iqmp(p, q),
        public_numbers=public_numbers,
    )
    return RSAKey(numbers.private_key(), kid=kid)


def _load_ec(jwk: Mapping[str, object]) -> ECKey:
    crv = _require_str(jwk, "crv")
    curve_type = _EC_CURVE_TYPES.get(crv)
    if curve_type is None:
        msg = f"unsupported EC curve: {crv!r}"
        raise JWKError(msg)
    public_numbers = ec.EllipticCurvePublicNumbers(
        x=_b64_to_int(_require_str(jwk, "x")),
        y=_b64_to_int(_require_str(jwk, "y")),
        curve=curve_type(),
    )
    kid = _optional_str(jwk, "kid")
    d_raw = _optional_str(jwk, "d")
    if d_raw is None:
        return ECKey(public_numbers.public_key(), kid=kid)
    numbers = ec.EllipticCurvePrivateNumbers(_b64_to_int(d_raw), public_numbers)
    return ECKey(numbers.private_key(), kid=kid)


def _load_okp(jwk: Mapping[str, object]) -> OKPKey:
    crv = _require_str(jwk, "crv")
    private_type = _OKP_PRIVATE_TYPES.get(crv)
    if private_type is None:
        msg = f"unsupported OKP curve: {crv!r}"
        raise JWKError(msg)
    x = b64url_decode(_require_str(jwk, "x").encode())
    kid = _optional_str(jwk, "kid")
    d_raw = _optional_str(jwk, "d")
    if d_raw is None:
        return OKPKey(_OKP_PUBLIC_TYPES[crv].from_public_bytes(x), kid=kid)
    private_key = private_type.from_private_bytes(b64url_decode(d_raw.encode()))
    if not bytes_eq(private_key.public_key().public_bytes_raw(), x):
        msg = "OKP public key does not match the private key"
        raise JWKError(msg)
    return OKPKey(private_key, kid=kid)


def _load_pem(pem: bytes, password: bytes | None) -> _PrivateKey | _PublicKey:
    loaded: object
    try:
        loaded = serialization.load_pem_private_key(pem, password=password)
    except ValueError:
        loaded = serialization.load_pem_public_key(pem)
    if isinstance(
        loaded,
        (
            rsa.RSAPrivateKey,
            rsa.RSAPublicKey,
            ec.EllipticCurvePrivateKey,
            ec.EllipticCurvePublicKey,
            ed25519.Ed25519PrivateKey,
            ed25519.Ed25519PublicKey,
            ed448.Ed448PrivateKey,
            ed448.Ed448PublicKey,
        ),
    ):
        return loaded
    msg = f"unsupported PEM key type: {type(loaded).__name__}"
    raise JWKError(msg)


def _from_crypto_key(key: _PrivateKey | _PublicKey) -> Key:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return RSAKey(key)
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return ECKey(key)
    return OKPKey(key)


_JWK_LOADERS: dict[str, Callable[[Mapping[str, object]], Key]] = {
    "oct": _load_oct,
    "RSA": _load_rsa,
    "EC": _load_ec,
    "OKP": _load_okp,
}
