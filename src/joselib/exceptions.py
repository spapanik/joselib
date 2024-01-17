class JOSEError(Exception):
    pass


class JWSError(JOSEError):
    pass


class JWSSignatureError(JWSError):
    pass


class JWSAlgorithmError(JWSError):
    pass


class JWTError(JOSEError):
    pass


class JWTClaimsError(JWTError):
    pass


class ExpiredSignatureError(JWTError):
    pass


class JWKError(JOSEError):
    pass


class JWEError(JOSEError):
    pass


class JWEParseError(JWEError):
    pass


class JWEInvalidAuthError(JWEError):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.__notes__ = [
            "The authentication tag did not match the protected sections of the JWE string provided"
        ]


class JWEAlgorithmUnsupportedError(JWEError):
    pass
