from __future__ import annotations

from joselib.keys.base import Key
from joselib.utils import base64url_encode, ensure_binary


class DIRKey(Key):
    def __init__(self, key_data, algorithm: str):
        self._key = ensure_binary(key_data)
        self._alg = algorithm

    def to_dict(self) -> dict[str, str | bytes]:
        return {
            "alg": self._alg,
            "kty": "oct",
            "k": base64url_encode(self._key),
        }
