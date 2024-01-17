from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, ClassVar

from joselib.types import HashFunction

if TYPE_CHECKING:
    from joselib.keys import Key


class Algorithms:
    # DS Algorithms
    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"

    # Content Encryption Algorithms
    A128CBC_HS256 = "A128CBC-HS256"
    A192CBC_HS384 = "A192CBC-HS384"
    A256CBC_HS512 = "A256CBC-HS512"
    A128GCM = "A128GCM"
    A192GCM = "A192GCM"
    A256GCM = "A256GCM"

    # Pseudo algorithm for encryption
    A128CBC = "A128CBC"
    A192CBC = "A192CBC"
    A256CBC = "A256CBC"

    # CEK Encryption Algorithms
    DIR = "dir"
    RSA1_5 = "RSA1_5"
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"
    A128KW = "A128KW"
    A192KW = "A192KW"
    A256KW = "A256KW"
    ECDH_ES = "ECDH-ES"
    ECDH_ES_A128KW = "ECDH-ES+A128KW"
    ECDH_ES_A192KW = "ECDH-ES+A192KW"
    ECDH_ES_A256KW = "ECDH-ES+A256KW"
    A128GCMKW = "A128GCMKW"
    A192GCMKW = "A192GCMKW"
    A256GCMKW = "A256GCMKW"
    PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
    PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
    PBES2_HS512_A256KW = "PBES2-HS512+A256KW"

    # Compression Algorithms
    DEF = "DEF"

    HMAC: ClassVar[set[str]] = {HS256, HS384, HS512}
    RSA_DS: ClassVar[set[str]] = {RS256, RS384, RS512}
    RSA_KW: ClassVar[set[str]] = {RSA1_5, RSA_OAEP, RSA_OAEP_256}
    RSA = RSA_DS.union(RSA_KW)
    EC_DS: ClassVar[set[str]] = {ES256, ES384, ES512}
    EC_KW: ClassVar[set[str]] = {
        ECDH_ES,
        ECDH_ES_A128KW,
        ECDH_ES_A192KW,
        ECDH_ES_A256KW,
    }
    EC = EC_DS.union(EC_KW)
    AES_PSEUDO: ClassVar[set[str]] = {
        A128CBC,
        A192CBC,
        A256CBC,
        A128GCM,
        A192GCM,
        A256GCM,
    }
    AES_JWE_ENC: ClassVar[set[str]] = {
        A128CBC_HS256,
        A192CBC_HS384,
        A256CBC_HS512,
        A128GCM,
        A192GCM,
        A256GCM,
    }
    AES_ENC = AES_JWE_ENC.union(AES_PSEUDO)
    AES_KW: ClassVar[set[str]] = {A128KW, A192KW, A256KW}
    AEC_GCM_KW: ClassVar[set[str]] = {A128GCMKW, A192GCMKW, A256GCMKW}
    AES = AES_ENC.union(AES_KW)
    PBES2_KW: ClassVar[set[str]] = {
        PBES2_HS256_A128KW,
        PBES2_HS384_A192KW,
        PBES2_HS512_A256KW,
    }

    HMAC_AUTH_TAG: ClassVar[set[str]] = {A128CBC_HS256, A192CBC_HS384, A256CBC_HS512}
    GCM: ClassVar[set[str]] = {A128GCM, A192GCM, A256GCM}

    SUPPORTED = (
        HMAC.union(RSA_DS)
        .union(EC_DS)
        .union([DIR])
        .union(AES_JWE_ENC)
        .union(RSA_KW)
        .union(AES_KW)
    )

    ALL = SUPPORTED.union([NONE]).union(AEC_GCM_KW).union(EC_KW).union(PBES2_KW)

    HASHES: ClassVar[dict[str, HashFunction]] = {
        HS256: hashlib.sha256,
        HS384: hashlib.sha384,
        HS512: hashlib.sha512,
        RS256: hashlib.sha256,
        RS384: hashlib.sha384,
        RS512: hashlib.sha512,
        ES256: hashlib.sha256,
        ES384: hashlib.sha384,
        ES512: hashlib.sha512,
    }

    KEYS: ClassVar[dict[str, type[Key]]] = {}


ALGORITHMS = Algorithms()


class Zips:
    DEF = "DEF"
    NONE = None
    SUPPORTED: ClassVar[set[str | None]] = {DEF, NONE}


ZIPS = Zips()
