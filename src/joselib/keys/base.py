from __future__ import annotations


class Key:
    def __init__(self, key, algorithm: str):
        pass

    def sign(self, msg: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, msg: bytes, sig: bytes) -> bool:
        raise NotImplementedError

    def public_key(self) -> Key:
        raise NotImplementedError

    def to_pem(self) -> bytes:
        raise NotImplementedError

    def to_dict(self) -> dict[str, str | bytes]:
        raise NotImplementedError

    def encrypt(
        self, plain_text: bytes, aad: bytes | None = None
    ) -> tuple[bytes, bytes, bytes]:
        raise NotImplementedError

    def decrypt(
        self,
        cipher_text: bytes,
        iv: bytes | None = None,
        aad: bytes | None = None,
        tag: bytes | None = None,
    ) -> bytes:
        raise NotImplementedError

    def wrap_key(self, key_data: bytes) -> bytes:
        raise NotImplementedError

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        raise NotImplementedError
