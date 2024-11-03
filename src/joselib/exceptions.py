class JoseError(Exception):
    """Base class for every error raised by joselib."""


class DecodeError(JoseError):
    """A token segment is not valid base64url or JSON."""


class UnsupportedAlgorithmError(JoseError):
    """An algorithm is not supported or not in the allowed set."""

    def __init__(self, algorithm: str) -> None:
        super().__init__(f"unsupported or disallowed algorithm: {algorithm!r}")
        self.algorithm = algorithm


class JWKError(JoseError):
    """A key cannot be imported, exported, or used as requested."""


class JWSError(JoseError):
    """A JWS token cannot be created or verified."""


class InvalidSignatureError(JWSError):
    """The signature of a JWS token does not match its content."""

    def __init__(self) -> None:
        super().__init__("signature verification failed")


class JWEError(JoseError):
    """A JWE token cannot be created or decrypted."""


class DecryptionError(JWEError):
    """A JWE token cannot be decrypted with the given key."""

    def __init__(self) -> None:
        super().__init__("token decryption failed")


class JWTError(JoseError):
    """A JWT cannot be created or its claims are invalid."""


class ExpiredTokenError(JWTError):
    """The token is past its expiration time."""

    def __init__(self) -> None:
        super().__init__("token has expired")


class InvalidClaimError(JWTError):
    """A claim is missing, has the wrong type, or an unexpected value."""

    def __init__(self, *, claim: str, reason: str) -> None:
        super().__init__(f"invalid {claim!r} claim: {reason}")
        self.claim = claim
        self.reason = reason
