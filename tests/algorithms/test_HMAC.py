import json

import pytest

from joselib.constants import ALGORITHMS
from joselib.exceptions import JOSEError
from joselib.keys import HMACKey


class TestHMACAlgorithm:
    @staticmethod
    def test_non_string_key() -> None:
        with pytest.raises(JOSEError):
            HMACKey(object(), ALGORITHMS.HS256)

    @staticmethod
    def test_RSA_key() -> None:
        key = "-----BEGIN PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "-----BEGIN RSA PUBLIC KEY-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "-----BEGIN CERTIFICATE-----"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

        key = "ssh-rsa"
        with pytest.raises(JOSEError):
            HMACKey(key, ALGORITHMS.HS256)

    @staticmethod
    def test_to_dict() -> None:
        passphrase = "The quick brown fox jumps over the lazy dog"
        encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw"
        key = HMACKey(passphrase, ALGORITHMS.HS256)

        as_dict = key.to_dict()
        assert "alg" in as_dict
        assert as_dict["alg"] == ALGORITHMS.HS256

        assert "kty" in as_dict
        assert as_dict["kty"] == "oct"

        assert "k" in as_dict
        assert as_dict["k"] == encoded

        # as_dict should be serializable to JSON
        json.dumps(as_dict)
