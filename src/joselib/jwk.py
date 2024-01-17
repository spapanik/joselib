from __future__ import annotations

from typing import Literal

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWKError
from joselib.keys import AESKey, DIRKey, ECKey, HMACKey, Key, RSAKey


def get_key(algorithm: str) -> type[Key] | None:
    if algorithm in ALGORITHMS.KEYS:
        return ALGORITHMS.KEYS[algorithm]
    if algorithm in ALGORITHMS.HMAC:
        return HMACKey
    if algorithm in ALGORITHMS.RSA:
        return RSAKey
    if algorithm in ALGORITHMS.EC:
        return ECKey
    if algorithm in ALGORITHMS.AES:
        return AESKey
    if algorithm == ALGORITHMS.DIR:
        return DIRKey
    return None


def register_key(algorithm: str, key_class: type[Key]) -> Literal[True]:
    if not issubclass(key_class, Key):
        msg = "Key class must be a subclass of Key"  # type: ignore[unreachable]
        raise TypeError(msg)
    ALGORITHMS.KEYS[algorithm] = key_class
    ALGORITHMS.SUPPORTED.add(algorithm)
    return True


def construct(key_data, algorithm: str | None = None) -> Key:
    """
    Construct a Key object for the given algorithm with the given
    key_data.
    """

    # Allow for pulling the algorithm off of the passed in jwk.
    if not algorithm and isinstance(key_data, dict):
        algorithm = key_data.get("alg", None)

    if not algorithm:
        msg = f"Unable to determine algorithm for key: {key_data}"
        raise JWKError(msg)

    key_class = get_key(algorithm)
    if not key_class:
        msg = f"Unable to find an algorithm for key: {key_data}"
        raise JWKError(msg)
    return key_class(key_data, algorithm)
