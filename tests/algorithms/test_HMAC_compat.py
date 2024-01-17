import pytest

from joselib.constants import ALGORITHMS
from joselib.keys import HMACKey

SUPPORTED_ALGORITHMS = ALGORITHMS.HMAC


class TestBackendAesCompatibility:
    @pytest.mark.parametrize("algorithm", ALGORITHMS.HMAC)
    def test_encryption_parity(self, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_sign = HMACKey(key, algorithm)
        key_verify = HMACKey(key, algorithm)

        message = b"test"

        digest = key_sign.sign(message)

        assert key_verify.verify(message, digest)

        assert not key_verify.verify(b"not the message", digest)

        assert not key_verify.verify(digest, b"not the digest")
