import json

import pytest
from cryptography.hazmat.backends import default_backend as CryptographyBackend
from cryptography.hazmat.primitives.asymmetric import ec as CryptographyEc

from joselib.constants import ALGORITHMS
from joselib.exceptions import JOSEError, JWKError
from joselib.keys import ECKey

private_key = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOiSs10XnBlfykk5zsJRmzYybKdMlGniSJcssDvUcF6DoAoGCCqGSM49
AwEHoUQDQgAE7gb4edKJ7ul9IgomCdcOebQTZ8qktqtBfRKboa71CfEKzBruUi+D
WkG0HJWIORlPbvXME+DRh6G/yVOKnTm88Q==
-----END EC PRIVATE KEY-----"""

# Private key generated using NIST256p curve
TOO_SHORT_PRIVATE_KEY = b"""\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMlUyYGOpjV4bbW0C9FKS2zkspD0L/5vJLnr6sJoLdc+oAoGCCqGSM49
AwEHoUQDQgAE6TDUNj5QXl+RKdZvBV+cg7Td6cJRB+Ta8XAhIuCAzonq0Ix//1+C
pNSsy11sIKmMl61YJzxvZ6WkNluBmkDPCQ==
-----END EC PRIVATE KEY-----
"""

# ES256 signatures generated to test conversion logic
DER_SIGNATURE = (
    b"0F\x02!\x00\x89yG\x81W\x01\x11\x9b0\x08\xa4\xd0\xe3g([\x07\xb5\x01\xb3"
    b"\x9d\xdf \xd1\xbc\xedK\x01\x87:}\xf2\x02!\x00\xb2shTA\x00\x1a\x13~\xba"
    b"J\xdb\xeem\x12\x1e\xfeMO\x04\xb2[\x86A\xbd\xc6hu\x953X\x1e"
)
RAW_SIGNATURE = (
    b"\x89yG\x81W\x01\x11\x9b0\x08\xa4\xd0\xe3g([\x07\xb5\x01\xb3\x9d\xdf "
    b"\xd1\xbc\xedK\x01\x87:}\xf2\xb2shTA\x00\x1a\x13~\xbaJ\xdb\xeem\x12\x1e"
    b"\xfeMO\x04\xb2[\x86A\xbd\xc6hu\x953X\x1e"
)


def _backend_exception_types():
    """Build the backend exception types based on available backends."""
    if ECKey is not None:
        yield ECKey, TypeError


@pytest.mark.parametrize(
    ("algorithm", "expected_length"),
    [(ALGORITHMS.ES256, 32), (ALGORITHMS.ES384, 48), (ALGORITHMS.ES512, 66)],
)
def test_cryptography_sig_component_length(algorithm, expected_length) -> None:
    # Put mapping inside here to avoid more complex handling for test runs that do not have pyca/cryptography
    mapping = {
        ALGORITHMS.ES256: CryptographyEc.SECP256R1,
        ALGORITHMS.ES384: CryptographyEc.SECP384R1,
        ALGORITHMS.ES512: CryptographyEc.SECP521R1,
    }
    key = ECKey(
        CryptographyEc.generate_private_key(
            mapping[algorithm](), backend=CryptographyBackend()
        ),
        algorithm,
    )
    assert key._sig_component_length() == expected_length


def test_cryptograhy_der_to_raw() -> None:
    key = ECKey(private_key, ALGORITHMS.ES256)
    assert key._der_to_raw(DER_SIGNATURE) == RAW_SIGNATURE


def test_cryptograhy_raw_to_der() -> None:
    key = ECKey(private_key, ALGORITHMS.ES256)
    assert key._raw_to_der(RAW_SIGNATURE) == DER_SIGNATURE


class TestECAlgorithm:
    @staticmethod
    def test_key_from_pem() -> None:
        assert not ECKey(private_key, ALGORITHMS.ES256).is_public()

    @staticmethod
    def test_to_pem() -> None:
        key = ECKey(private_key, ALGORITHMS.ES256)
        assert not key.is_public()
        assert key.to_pem().strip() == private_key.strip().encode("utf-8")

        public_pem = key.public_key().to_pem()
        assert ECKey(public_pem, ALGORITHMS.ES256).is_public()

    @staticmethod
    @pytest.mark.parametrize(("Backend", "ExceptionType"), _backend_exception_types())
    def test_key_too_short(Backend, ExceptionType) -> None:
        key = Backend(TOO_SHORT_PRIVATE_KEY, ALGORITHMS.ES512)
        with pytest.raises(ExceptionType):
            key.sign(b"foo")

    @staticmethod
    def test_get_public_key() -> None:
        key = ECKey(private_key, ALGORITHMS.ES256)
        pubkey = key.public_key()
        pubkey2 = pubkey.public_key()
        assert pubkey == pubkey2

    @staticmethod
    def test_string_secret() -> None:
        key = "secret"
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)

    @staticmethod
    def test_object() -> None:
        key = object()
        with pytest.raises(JOSEError):
            ECKey(key, ALGORITHMS.ES256)

    @staticmethod
    def test_invalid_algorithm() -> None:
        with pytest.raises(JWKError):
            ECKey(private_key, "nonexistent")

        with pytest.raises(JWKError):
            ECKey({"kty": "bla"}, ALGORITHMS.ES256)

    @staticmethod
    def test_EC_jwk() -> None:
        key = {
            "kty": "EC",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "crv": "P-521",
            "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
            "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
        }

        assert not ECKey(key, ALGORITHMS.ES512).is_public()

        del key["d"]

        # We are now dealing with a public key.
        assert ECKey(key, ALGORITHMS.ES512).is_public()

        del key["x"]

        # This key is missing a required parameter.
        with pytest.raises(JWKError):
            ECKey(key, ALGORITHMS.ES512)

    @staticmethod
    def test_verify() -> None:
        key = ECKey(private_key, ALGORITHMS.ES256)
        msg = b"test"
        signature = key.sign(msg)
        public_key = key.public_key()

        assert bool(public_key.verify(msg, signature))
        assert not bool(public_key.verify(msg, b"not a signature"))

    @staticmethod
    def assert_parameters(as_dict, private) -> None:
        assert isinstance(as_dict, dict)

        # Public parameters should always be there.
        assert "x" in as_dict
        assert "y" in as_dict
        assert "crv" in as_dict

        assert "kty" in as_dict
        assert as_dict["kty"] == "EC"

        if private:
            # Private parameters as well
            assert "d" in as_dict

        else:
            # Private parameters should be absent
            assert "d" not in as_dict

        # as_dict should be serializable to JSON
        json.dumps(as_dict)

    def test_to_dict(self) -> None:
        key = ECKey(private_key, ALGORITHMS.ES256)
        self.assert_parameters(key.to_dict(), private=True)
        self.assert_parameters(key.public_key().to_dict(), private=False)
