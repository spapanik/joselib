from __future__ import annotations

import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import load_pem_x509_certificate

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWEError, JWKError
from joselib.keys.base import Key
from joselib.utils import base64_to_long, long_to_base64


class RSAKey(Key):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    RSA1_5 = padding.PKCS1v15()
    RSA_OAEP = padding.OAEP(
        padding.MGF1(hashes.SHA1()), hashes.SHA1(), None  # noqa: S303
    )
    RSA_OAEP_256 = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)

    def __init__(self, key, algorithm: str, cryptography_backend=default_backend):
        if algorithm not in ALGORITHMS.RSA:
            msg = f"hash_alg: {algorithm} is not a valid hash algorithm"
            raise JWKError(msg)

        self.hash_alg = {
            ALGORITHMS.RS256: self.SHA256,
            ALGORITHMS.RS384: self.SHA384,
            ALGORITHMS.RS512: self.SHA512,
        }.get(algorithm)
        self._algorithm = algorithm

        self.padding = {
            ALGORITHMS.RSA1_5: self.RSA1_5,
            ALGORITHMS.RSA_OAEP: self.RSA_OAEP,
            ALGORITHMS.RSA_OAEP_256: self.RSA_OAEP_256,
        }.get(algorithm)

        self.cryptography_backend = cryptography_backend

        # if it conforms to RSAPublicKey interface
        if hasattr(key, "public_bytes") and hasattr(key, "public_numbers"):
            self.prepared_key = key
            return

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, str):
            key = key.encode("utf-8")

        if isinstance(key, bytes):
            try:
                if key.startswith(b"-----BEGIN CERTIFICATE-----"):
                    self._process_cert(key)
                    return

                try:
                    self.prepared_key = load_pem_public_key(
                        key, self.cryptography_backend()
                    )
                except ValueError:
                    self.prepared_key = load_pem_private_key(
                        key, password=None, backend=self.cryptography_backend()
                    )
            except Exception as err:
                raise JWKError(err) from err
            return

        msg = f"Unable to parse an RSAKey from key: {key}"
        raise JWKError(msg)

    def _process_jwk(
        self, jwk_dict: dict[str, str]
    ) -> rsa.RSAPublicKey | rsa.RSAPublicKey:
        if jwk_dict.get("kty") != "RSA":
            kty = jwk_dict.get("kty")
            msg = f"Incorrect key type. Expected: 'RSA', Received: {kty}"
            raise JWKError(msg)

        e = base64_to_long(jwk_dict.get("e", 256))
        n = base64_to_long(jwk_dict.get("n"))
        public = rsa.RSAPublicNumbers(e, n)

        if "d" not in jwk_dict:
            return public.public_key(self.cryptography_backend())
        # This is a private key.
        d = base64_to_long(jwk_dict.get("d"))

        extra_params = ["p", "q", "dp", "dq", "qi"]

        if any(k in jwk_dict for k in extra_params):
            # Precomputed private key parameters are available.
            if any(k not in jwk_dict for k in extra_params):
                # These values must be present when 'p' is according to
                # Section 6.3.2 of RFC7518, so if they are not we raise
                # an error.
                msg = "Precomputed private key parameters are incomplete."
                raise JWKError(msg)

            p = base64_to_long(jwk_dict["p"])
            q = base64_to_long(jwk_dict["q"])
            dp = base64_to_long(jwk_dict["dp"])
            dq = base64_to_long(jwk_dict["dq"])
            qi = base64_to_long(jwk_dict["qi"])
        else:
            # The precomputed private key parameters are not available,
            # so we use cryptography's API to fill them in.
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
            dp = rsa.rsa_crt_dmp1(d, p)
            dq = rsa.rsa_crt_dmq1(d, q)
            qi = rsa.rsa_crt_iqmp(p, q)

        private = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public)

        return private.private_key(self.cryptography_backend())

    def _process_cert(self, key) -> None:
        key = load_pem_x509_certificate(key, self.cryptography_backend())
        self.prepared_key = key.public_key()

    def sign(self, msg: bytes) -> bytes:
        try:
            signature = self.prepared_key.sign(msg, padding.PKCS1v15(), self.hash_alg())
        except Exception as err:
            raise JWKError(err) from err
        return signature

    def verify(self, msg: bytes, sig: bytes) -> bool:
        if not self.is_public():
            warn_msg = "Attempting to verify a message with a private key. This is not recommended."
            warnings.warn(warn_msg, UserWarning, stacklevel=2)

        try:
            self.public_key().prepared_key.verify(
                sig, msg, padding.PKCS1v15(), self.hash_alg()
            )
        except InvalidSignature:
            return False
        return True

    def is_public(self) -> bool:
        return hasattr(self.prepared_key, "public_bytes")

    def public_key(self) -> RSAKey:
        if self.is_public():
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self, pem_format: str = "PKCS8") -> bytes:
        if self.is_public():
            if pem_format == "PKCS8":
                fmt = serialization.PublicFormat.SubjectPublicKeyInfo
            elif pem_format == "PKCS1":
                fmt = serialization.PublicFormat.PKCS1
            else:
                msg = f"Invalid format specified: {pem_format}"
                raise ValueError(msg)
            return self.prepared_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=fmt
            )

        if pem_format == "PKCS8":
            fmt = serialization.PrivateFormat.PKCS8
        elif pem_format == "PKCS1":
            fmt = serialization.PrivateFormat.TraditionalOpenSSL
        else:
            msg = f"Invalid format specified: {pem_format}"
            raise ValueError(msg)

        return self.prepared_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=fmt,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def to_dict(self) -> dict[str, str | bytes]:
        if not self.is_public():
            public_key = self.prepared_key.public_key()
        else:
            public_key = self.prepared_key

        data = {
            "alg": self._algorithm,
            "kty": "RSA",
            "n": long_to_base64(public_key.public_numbers().n).decode("ASCII"),
            "e": long_to_base64(public_key.public_numbers().e).decode("ASCII"),
        }

        if not self.is_public():
            data |= {
                "d": long_to_base64(self.prepared_key.private_numbers().d).decode(
                    "ASCII"
                ),
                "p": long_to_base64(self.prepared_key.private_numbers().p).decode(
                    "ASCII"
                ),
                "q": long_to_base64(self.prepared_key.private_numbers().q).decode(
                    "ASCII"
                ),
                "dp": long_to_base64(self.prepared_key.private_numbers().dmp1).decode(
                    "ASCII"
                ),
                "dq": long_to_base64(self.prepared_key.private_numbers().dmq1).decode(
                    "ASCII"
                ),
                "qi": long_to_base64(self.prepared_key.private_numbers().iqmp).decode(
                    "ASCII"
                ),
            }

        return data

    def wrap_key(self, key_data: bytes) -> bytes:
        try:
            wrapped_key = self.prepared_key.encrypt(key_data, self.padding)
        except Exception as err:
            raise JWEError(err) from err

        return wrapped_key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        try:
            unwrapped_key = self.prepared_key.decrypt(wrapped_key, self.padding)
        except Exception as err:
            raise JWEError(err) from err
        else:
            return unwrapped_key
