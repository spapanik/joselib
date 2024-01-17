import pytest

from joselib.constants import ALGORITHMS
from joselib.exceptions import JWEError
from joselib.keys import AESKey


class TestBackendAesCompatibility:
    @pytest.mark.parametrize("algorithm", ALGORITHMS.AES_PSEUDO)
    def test_encryption_parity(self, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_encrypt = AESKey(key, algorithm)
        key_decrypt = AESKey(key, algorithm)
        plain_text = b"test"
        aad = b"extra data" if "GCM" in algorithm else None

        iv, cipher_text, tag = key_encrypt.encrypt(plain_text, aad)

        # verify decrypt to original plain text
        actual = key_decrypt.decrypt(cipher_text, iv, aad, tag)
        assert actual == plain_text

        with pytest.raises(JWEError):
            key_decrypt.decrypt(b"n" * 64)

    @pytest.mark.parametrize("algorithm", ALGORITHMS.AES_KW)
    def test_wrap_parity(self, algorithm):
        if "128" in algorithm:
            key = b"8slRzzty6dKMaFCP"
        elif "192" in algorithm:
            key = b"8slRzzty6dKMaFCP8slRzzty"
        else:
            key = b"8slRzzty6dKMaFCP8slRzzty6dKMaFCP"

        key_wrap = AESKey(key, algorithm)
        key_unwrap = AESKey(key, algorithm)
        plain_text = b"sixteen byte key"

        wrapped_key = key_wrap.wrap_key(plain_text)

        # verify unwrap_key to original plain text
        actual = key_unwrap.unwrap_key(wrapped_key)
        assert actual == plain_text

        with pytest.raises(JWEError):
            key_unwrap.decrypt(b"n" * 64)
