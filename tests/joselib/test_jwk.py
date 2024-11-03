import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
)

from joselib.exceptions import DecodeError, JWKError
from joselib.jwk import ECKey, Key, OctKey, OKPKey, RSAKey, _int_to_b64
from joselib.utils import json_encode

# The RSA key and its thumbprint from RFC 7638, section 3.1.
RFC_7638_N = (
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1"
    "L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4"
    "QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO"
    "pbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"
    "Cur-kEgU8awapJzKnqDKgw"
)
RFC_7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


class TestKeyDispatch:
    def test_from_jwk_accepts_str_and_bytes(self, oct_key: OctKey) -> None:
        jwk = json_encode(oct_key.to_jwk(private=True))
        assert isinstance(Key.from_jwk(jwk), OctKey)
        assert isinstance(Key.from_jwk(jwk.decode()), OctKey)

    def test_from_jwk_missing_kty(self) -> None:
        with pytest.raises(JWKError):
            Key.from_jwk({})

    def test_from_jwk_non_string_kty(self) -> None:
        with pytest.raises(JWKError):
            Key.from_jwk({"kty": 5})

    def test_from_jwk_unknown_kty(self) -> None:
        with pytest.raises(JWKError):
            Key.from_jwk({"kty": "PQC"})

    def test_from_jwk_type_mismatch(self, oct_key: OctKey) -> None:
        with pytest.raises(JWKError):
            ECKey.from_jwk(oct_key.to_jwk(private=True))

    def test_from_jwk_invalid_base64_field(self) -> None:
        with pytest.raises(JWKError):
            Key.from_jwk({"kty": "oct", "k": "!!"})

    def test_from_jwk_duplicate_json_keys(self) -> None:
        with pytest.raises(DecodeError):
            Key.from_jwk('{"kty":"oct","kty":"oct"}')

    def test_from_jwk_non_string_kid(self) -> None:
        jwk = OctKey.generate().to_jwk(private=True) | {"kid": 5}
        with pytest.raises(JWKError):
            Key.from_jwk(jwk)

    def test_from_pem_garbage(self) -> None:
        with pytest.raises(JWKError):
            Key.from_pem(b"not a pem")

    def test_from_pem_wrong_password(self, ec_key: ECKey) -> None:
        with pytest.raises(JWKError):
            Key.from_pem(ec_key.to_pem(private=True), password=b"hunter2")

    def test_from_pem_unsupported_key_type(self) -> None:
        pem = x25519.X25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"hunter2")
        )
        with pytest.raises(JWKError):
            Key.from_pem(pem, password=b"hunter2")

    def test_from_pem_type_mismatch(self, rsa_key: RSAKey) -> None:
        with pytest.raises(JWKError):
            ECKey.from_pem(rsa_key.to_pem())

    def test_from_pem_encrypted_private_key(self, ec_key: ECKey) -> None:
        pem = ec_key.crypto_private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"hunter2")
        )
        restored = ECKey.from_pem(pem, password=b"hunter2")
        assert restored.thumbprint() == ec_key.thumbprint()


class TestOctKey:
    def test_generate(self) -> None:
        key = OctKey.generate()
        assert len(key.secret) == 32
        assert key.is_private

    def test_rejects_short_keys(self) -> None:
        with pytest.raises(JWKError):
            OctKey.generate(8)

    def test_has_no_public_part(self) -> None:
        with pytest.raises(JWKError):
            OctKey.generate().public()

    def test_export_requires_private(self, oct_key: OctKey) -> None:
        with pytest.raises(JWKError):
            oct_key.to_jwk()

    def test_jwk_round_trip(self, oct_key: OctKey) -> None:
        restored = OctKey.from_jwk(oct_key.to_jwk(private=True))
        assert restored.secret == oct_key.secret
        assert restored.kid is None

    def test_missing_k(self) -> None:
        with pytest.raises(JWKError):
            Key.from_jwk({"kty": "oct"})

    def test_kid_round_trip(self) -> None:
        key = OctKey(b"\x00" * 16, kid="a-kid")
        restored = OctKey.from_jwk(key.to_jwk(private=True))
        assert restored.kid == "a-kid"

    def test_thumbprint(self, oct_key: OctKey) -> None:
        assert oct_key.thumbprint() == oct_key.thumbprint()
        assert oct_key.thumbprint() != OctKey.generate().thumbprint()


class TestRSAKey:
    def test_generate_rejects_small_sizes(self) -> None:
        with pytest.raises(JWKError):
            RSAKey.generate(1024)

    def test_rejects_small_keys(self) -> None:
        # A deliberately breakable size, to test that it gets rejected.
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
        with pytest.raises(JWKError):
            RSAKey(small)

    def test_jwk_round_trip_private(self, rsa_key: RSAKey) -> None:
        restored = RSAKey.from_jwk(rsa_key.to_jwk(private=True))
        assert restored.is_private
        assert restored.thumbprint() == rsa_key.thumbprint()

    def test_jwk_round_trip_public(self, rsa_key: RSAKey) -> None:
        restored = RSAKey.from_jwk(rsa_key.to_jwk())
        assert not restored.is_private
        assert restored.thumbprint() == rsa_key.thumbprint()

    def test_jwk_private_import_without_primes(self, rsa_key: RSAKey) -> None:
        jwk = rsa_key.to_jwk(private=True)
        minimal = {"kty": "RSA", "n": jwk["n"], "e": jwk["e"], "d": jwk["d"]}
        restored = RSAKey.from_jwk(minimal)
        assert restored.is_private
        assert restored.to_jwk(private=True)["p"] in (jwk["p"], jwk["q"])

    def test_jwk_private_import_without_crt_params(self, rsa_key: RSAKey) -> None:
        jwk = rsa_key.to_jwk(private=True)
        for field in ("dp", "dq", "qi"):
            del jwk[field]
        restored = RSAKey.from_jwk(jwk)
        assert restored.to_jwk(private=True) == rsa_key.to_jwk(private=True)

    def test_public(self, rsa_key: RSAKey) -> None:
        public = rsa_key.public()
        assert not public.is_private
        assert public.public() is public
        assert public.thumbprint() == rsa_key.thumbprint()

    def test_public_key_cannot_sign_or_export_private(self, rsa_key: RSAKey) -> None:
        public = rsa_key.public()
        with pytest.raises(JWKError):
            _ = public.crypto_private_key
        with pytest.raises(JWKError):
            public.to_jwk(private=True)
        with pytest.raises(JWKError):
            public.to_pem(private=True)

    def test_pem_round_trip(self, rsa_key: RSAKey) -> None:
        assert RSAKey.from_pem(rsa_key.to_pem(private=True)).is_private
        public = RSAKey.from_pem(rsa_key.to_pem())
        assert not public.is_private
        assert public.thumbprint() == rsa_key.thumbprint()

    def test_kid_is_preserved(self, rsa_key: RSAKey) -> None:
        key = RSAKey(rsa_key.crypto_private_key, kid="a-kid")
        assert key.public().kid == "a-kid"
        assert key.to_jwk()["kid"] == "a-kid"
        assert RSAKey.from_jwk(key.to_jwk(private=True)).kid == "a-kid"

    def test_rfc_7638_thumbprint(self) -> None:
        key = RSAKey.from_jwk({"kty": "RSA", "n": RFC_7638_N, "e": "AQAB"})
        assert key.thumbprint() == RFC_7638_THUMBPRINT


class TestECKey:
    @pytest.mark.parametrize("curve", ["P-256", "P-384", "P-521"])
    def test_jwk_round_trip(self, curve: str) -> None:
        key = ECKey.generate(curve)
        assert key.curve == curve
        restored = ECKey.from_jwk(key.to_jwk(private=True))
        assert restored.is_private
        assert restored.curve == curve
        assert restored.thumbprint() == key.thumbprint()
        public = ECKey.from_jwk(key.to_jwk())
        assert not public.is_private
        assert public.thumbprint() == key.thumbprint()

    def test_generate_unknown_curve(self) -> None:
        with pytest.raises(JWKError):
            ECKey.generate("P-128")

    def test_rejects_unsupported_curves(self) -> None:
        secp256k1 = ec.generate_private_key(ec.SECP256K1())
        with pytest.raises(JWKError):
            ECKey(secp256k1)

    def test_from_jwk_unknown_curve(self, ec_key: ECKey) -> None:
        jwk = ec_key.to_jwk() | {"crv": "P-128"}
        with pytest.raises(JWKError):
            ECKey.from_jwk(jwk)

    def test_from_jwk_missing_coordinate(self, ec_key: ECKey) -> None:
        jwk = ec_key.to_jwk()
        del jwk["y"]
        with pytest.raises(JWKError):
            ECKey.from_jwk(jwk)

    def test_from_jwk_point_not_on_curve(self) -> None:
        jwk = {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"}
        with pytest.raises(JWKError):
            ECKey.from_jwk(jwk)

    def test_public(self, ec_key: ECKey) -> None:
        public = ec_key.public()
        assert not public.is_private
        assert public.public() is public
        with pytest.raises(JWKError):
            _ = public.crypto_private_key

    def test_pem_round_trip(self, ec_key: ECKey) -> None:
        assert ECKey.from_pem(ec_key.to_pem(private=True)).is_private
        public = ECKey.from_pem(ec_key.to_pem())
        assert not public.is_private
        assert public.thumbprint() == ec_key.thumbprint()

    def test_kid_is_preserved(self, ec_key: ECKey) -> None:
        key = ECKey(ec_key.crypto_private_key, kid="a-kid")
        assert key.to_jwk()["kid"] == "a-kid"
        assert ECKey.from_jwk(key.to_jwk(private=True)).kid == "a-kid"


class TestOKPKey:
    @pytest.mark.parametrize("curve", ["Ed25519", "Ed448"])
    def test_jwk_round_trip(self, curve: str) -> None:
        key = OKPKey.generate(curve)
        assert key.curve == curve
        restored = OKPKey.from_jwk(key.to_jwk(private=True))
        assert restored.is_private
        assert restored.curve == curve
        assert restored.thumbprint() == key.thumbprint()
        public = OKPKey.from_jwk(key.to_jwk())
        assert not public.is_private
        assert public.thumbprint() == key.thumbprint()

    def test_generate_unknown_curve(self) -> None:
        with pytest.raises(JWKError):
            OKPKey.generate("X25519")

    def test_from_jwk_unknown_curve(self, okp_key: OKPKey) -> None:
        jwk = okp_key.to_jwk() | {"crv": "X25519"}
        with pytest.raises(JWKError):
            OKPKey.from_jwk(jwk)

    def test_from_jwk_mismatched_public_part(self, okp_key: OKPKey) -> None:
        jwk = okp_key.to_jwk(private=True)
        jwk["x"] = OKPKey.generate().to_jwk()["x"]
        with pytest.raises(JWKError):
            OKPKey.from_jwk(jwk)

    def test_from_jwk_invalid_key_length(self) -> None:
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "AQID"}
        with pytest.raises(JWKError):
            OKPKey.from_jwk(jwk)

    def test_public(self, okp_key: OKPKey) -> None:
        public = okp_key.public()
        assert not public.is_private
        assert public.public() is public
        with pytest.raises(JWKError):
            _ = public.crypto_private_key
        with pytest.raises(JWKError):
            public.to_jwk(private=True)

    def test_pem_round_trip(self, okp_key: OKPKey) -> None:
        assert OKPKey.from_pem(okp_key.to_pem(private=True)).is_private
        public = OKPKey.from_pem(okp_key.to_pem())
        assert not public.is_private
        assert public.thumbprint() == okp_key.thumbprint()

    def test_kid_is_preserved(self, okp_key: OKPKey) -> None:
        key = OKPKey(okp_key.crypto_private_key, kid="a-kid")
        assert key.to_jwk()["kid"] == "a-kid"
        assert OKPKey.from_jwk(key.to_jwk(private=True)).kid == "a-kid"


class TestHelpers:
    def test_int_to_b64_zero(self) -> None:
        assert _int_to_b64(0) == "AA"

    def test_kid_is_read_only(self, oct_key: OctKey) -> None:
        with pytest.raises(AttributeError):
            oct_key.kid = "other"  # type: ignore[misc]  # ty: ignore[invalid-assignment]
