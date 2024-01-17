from __future__ import annotations

import math

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.utils import int_to_bytes

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWKError
from joselib.keys.base import Key
from joselib.utils import base64_to_long, long_to_base64


class ECKey(Key):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    def __init__(self, key, algorithm: str, cryptography_backend=default_backend):
        if algorithm not in ALGORITHMS.EC:
            msg = f"hash_alg: {algorithm} is not a valid hash algorithm"
            raise JWKError(msg)

        self.hash_alg = {
            ALGORITHMS.ES256: self.SHA256,
            ALGORITHMS.ES384: self.SHA384,
            ALGORITHMS.ES512: self.SHA512,
        }.get(algorithm)
        self._algorithm = algorithm

        self.cryptography_backend = cryptography_backend

        if hasattr(key, "public_bytes") or hasattr(key, "private_bytes"):
            self.prepared_key = key
            return

        if hasattr(key, "to_pem"):
            # convert to PEM and let cryptography below load it as PEM
            key = key.to_pem().decode("utf-8")

        if isinstance(key, dict):
            self.prepared_key = self._process_jwk(key)
            return

        if isinstance(key, str):
            key = key.encode("utf-8")

        if isinstance(key, bytes):
            # Attempt to load key. We don't know if it's
            # a Public Key or a Private Key, so we try
            # the Public Key first.
            try:
                try:
                    key = load_pem_public_key(key, self.cryptography_backend())
                except ValueError:
                    key = load_pem_private_key(
                        key, password=None, backend=self.cryptography_backend()
                    )
            except Exception as err:
                raise JWKError(err) from err

            self.prepared_key = key
            return

        msg = f"Unable to parse an ECKey from key: {key}"
        raise JWKError(msg)

    def _process_jwk(self, jwk_dict: dict[str, str]) -> Key:
        if jwk_dict.get("kty") != "EC":
            kty = jwk_dict.get("kty")
            msg = f"Incorrect key type. Expected: 'EC', Received: {kty}"
            raise JWKError(msg)

        if any(k not in jwk_dict for k in ["x", "y", "crv"]):
            msg = "Mandatory parameters are missing"
            raise JWKError(msg)

        x = base64_to_long(jwk_dict.get("x"))
        y = base64_to_long(jwk_dict.get("y"))
        curve = {
            "P-256": ec.SECP256R1,
            "P-384": ec.SECP384R1,
            "P-521": ec.SECP521R1,
        }[jwk_dict["crv"]]

        public = ec.EllipticCurvePublicNumbers(x, y, curve())

        if "d" in jwk_dict:
            d = base64_to_long(jwk_dict.get("d"))
            private = ec.EllipticCurvePrivateNumbers(d, public)

            return private.private_key(self.cryptography_backend())

        return public.public_key(self.cryptography_backend())

    def _sig_component_length(self) -> int:
        """Determine the correct serialization length for an encoded signature component.

        This is the number of bytes required to encode the maximum key value.
        """
        return int(math.ceil(self.prepared_key.key_size / 8.0))

    def _der_to_raw(self, der_signature: bytes) -> bytes:
        """Convert signature from DER encoding to RAW encoding."""
        r, s = decode_dss_signature(der_signature)
        component_length = self._sig_component_length()
        return int_to_bytes(r, component_length) + int_to_bytes(s, component_length)

    def _raw_to_der(self, raw_signature: bytes) -> bytes:
        """Convert signature from RAW encoding to DER encoding."""
        component_length = self._sig_component_length()
        if len(raw_signature) != int(2 * component_length):
            msg = "Invalid signature length"
            raise ValueError(msg)

        r_bytes = raw_signature[:component_length]
        s_bytes = raw_signature[component_length:]
        r = int.from_bytes(r_bytes, "big")
        s = int.from_bytes(s_bytes, "big")
        return encode_dss_signature(r, s)

    def sign(self, msg: bytes) -> bytes:
        if self.hash_alg.digest_size * 8 > self.prepared_key.curve.key_size:
            error_message = f"this curve ({self.prepared_key.curve.name}) is too short for your digest ({8 * self.hash_alg.digest_size})"
            raise TypeError(error_message)
        signature = self.prepared_key.sign(msg, ec.ECDSA(self.hash_alg()))
        return self._der_to_raw(signature)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            signature = self._raw_to_der(sig)
            self.prepared_key.verify(signature, msg, ec.ECDSA(self.hash_alg()))
        except Exception:
            return False
        else:
            return True

    def is_public(self) -> bool:
        return hasattr(self.prepared_key, "public_bytes")

    def public_key(self) -> Key:
        if self.is_public():
            return self
        return self.__class__(self.prepared_key.public_key(), self._algorithm)

    def to_pem(self) -> bytes:
        if self.is_public():
            return self.prepared_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        return self.prepared_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def to_dict(self) -> dict[str, str | bytes]:
        if not self.is_public():
            public_key = self.prepared_key.public_key()
        else:
            public_key = self.prepared_key

        crv = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }[self.prepared_key.curve.name]

        # Calculate the key size in bytes. Section 6.2.1.2 and 6.2.1.3 of
        # RFC7518 prescribes that the 'x', 'y' and 'd' parameters of the curve
        # points must be encoded as octed-strings of this length.
        key_size = (self.prepared_key.curve.key_size + 7) // 8

        data = {
            "alg": self._algorithm,
            "kty": "EC",
            "crv": crv,
            "x": long_to_base64(public_key.public_numbers().x, size=key_size).decode(
                "ASCII"
            ),
            "y": long_to_base64(public_key.public_numbers().y, size=key_size).decode(
                "ASCII"
            ),
        }

        if not self.is_public():
            private_value = self.prepared_key.private_numbers().private_value
            data["d"] = long_to_base64(private_value, size=key_size).decode("ASCII")

        return data
