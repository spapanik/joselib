from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING

from joselib.exceptions import ExpiredTokenError, InvalidClaimError, JWTError
from joselib.jws import JWS
from joselib.utils import json_decode, json_encode

if TYPE_CHECKING:
    from collections.abc import Mapping, Set as AbstractSet

    from joselib.jwk import Key

_TIME_CLAIMS = ("exp", "nbf", "iat")


def _normalize_claims(claims: Mapping[str, object]) -> Mapping[str, object]:
    updates: dict[str, object] = {}
    for name in _TIME_CLAIMS:
        value = claims.get(name)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                msg = f"claim {name!r} must be a timezone-aware datetime"
                raise JWTError(msg)
            updates[name] = int(value.timestamp())
    if not updates:
        return claims
    return {**claims, **updates}


def _numeric_claim(claims: Mapping[str, object], name: str) -> float | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidClaimError(claim=name, reason="must be a number")
    return value


def _string_claim(claims: Mapping[str, object], name: str) -> str | None:
    value = claims.get(name)
    if value is not None and not isinstance(value, str):
        raise InvalidClaimError(claim=name, reason="must be a string")
    return value


class JWT:
    __slots__ = ("_audience", "_issuer", "_jws", "_leeway", "_required")

    def __init__(
        self,
        key: Key,
        algorithm: str,
        *,
        allowed_algorithms: AbstractSet[str] | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        leeway: float = 0,
        required_claims: AbstractSet[str] = frozenset(),
    ) -> None:
        self._jws = JWS(
            key,
            algorithm,
            allowed_algorithms=allowed_algorithms,
            headers={"typ": "JWT"},
        )
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway
        self._required = frozenset(required_claims)

    def encode(
        self,
        claims: Mapping[str, object],
        *,
        headers: Mapping[str, object] | None = None,
    ) -> str:
        payload = json_encode(_normalize_claims(claims))
        return self._jws.sign(payload, headers=headers)

    def decode(self, token: str | bytes) -> dict[str, object]:
        claims = json_decode(self._jws.verify(token))
        self._validate_claims(claims)
        return claims

    def _validate_claims(self, claims: Mapping[str, object]) -> None:
        for name in self._required:
            if name not in claims:
                raise InvalidClaimError(claim=name, reason="required claim is missing")
        now = time.time()
        expiration = _numeric_claim(claims, "exp")
        if expiration is not None and expiration < now - self._leeway:
            raise ExpiredTokenError
        not_before = _numeric_claim(claims, "nbf")
        if not_before is not None and not_before > now + self._leeway:
            raise InvalidClaimError(claim="nbf", reason="token is not yet valid")
        _numeric_claim(claims, "iat")
        _string_claim(claims, "sub")
        _string_claim(claims, "jti")
        self._validate_issuer(claims)
        self._validate_audience(claims)

    def _validate_issuer(self, claims: Mapping[str, object]) -> None:
        issuer = _string_claim(claims, "iss")
        if self._issuer is not None and issuer != self._issuer:
            raise InvalidClaimError(claim="iss", reason="issuer does not match")

    def _validate_audience(self, claims: Mapping[str, object]) -> None:
        audience = claims.get("aud")
        if audience is None:
            if self._audience is not None:
                raise InvalidClaimError(claim="aud", reason="required claim is missing")
            return
        if self._audience is None:
            raise InvalidClaimError(
                claim="aud", reason="token has an audience, but none is expected"
            )
        if isinstance(audience, str):
            audiences: list[str] = [audience]
        elif isinstance(audience, list) and all(
            isinstance(item, str) for item in audience
        ):
            audiences = audience
        else:
            raise InvalidClaimError(
                claim="aud", reason="must be a string or a list of strings"
            )
        if self._audience not in audiences:
            raise InvalidClaimError(claim="aud", reason="audience does not match")
