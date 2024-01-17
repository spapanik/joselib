import pytest

from joselib import jwk
from joselib.exceptions import JWKError
from joselib.keys import ECKey, HMACKey, Key, RSAKey

hmac_key = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}

rsa_key = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
}

ec_key = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
}


class TestJWK:
    @staticmethod
    def test_interface() -> None:
        key = jwk.Key("key", "ALG")

        with pytest.raises(NotImplementedError):
            key.sign("")

        with pytest.raises(NotImplementedError):
            key.verify("", "")

    @staticmethod
    def test_invalid_hash_alg() -> None:
        with pytest.raises(JWKError):
            key = HMACKey(hmac_key, "RS512")

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS512")

        with pytest.raises(JWKError):
            key = ECKey(ec_key, "RS512")  # noqa: F841

    @staticmethod
    def test_invalid_jwk() -> None:
        with pytest.raises(JWKError):
            key = HMACKey(rsa_key, "HS256")

        with pytest.raises(JWKError):
            key = RSAKey(hmac_key, "RS256")

        with pytest.raises(JWKError):
            key = ECKey(rsa_key, "ES256")  # noqa: F841

    @staticmethod
    def test_RSAKey_errors() -> None:
        rsa_key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "HS256")

        rsa_key = {
            "kty": "oct",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, "RS256")  # noqa: F841

    @staticmethod
    def test_construct_from_jwk() -> None:
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        key = jwk.construct(hmac_key)
        assert isinstance(key, jwk.Key)

    @staticmethod
    def test_construct_EC_from_jwk() -> None:
        key = ECKey(ec_key, algorithm="ES512")
        assert isinstance(key, jwk.Key)

    @staticmethod
    def test_construct_from_jwk_missing_alg() -> None:
        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
        }

        with pytest.raises(JWKError):
            key = jwk.construct(hmac_key)

        with pytest.raises(JWKError):
            key = jwk.construct("key", algorithm="NONEXISTENT")  # noqa: F841

    @staticmethod
    def test_get_key() -> None:
        hs_key = jwk.get_key("HS256")
        assert hs_key == HMACKey
        assert issubclass(hs_key, Key)
        if RSAKey is not None:
            assert issubclass(jwk.get_key("RS256"), Key)
        assert issubclass(jwk.get_key("ES256"), Key)

        assert jwk.get_key("NONEXISTENT") is None

    @staticmethod
    def test_get_aes_key() -> None:
        assert issubclass(jwk.get_key("A256CBC-HS512"), Key)

    @staticmethod
    def test_register_key() -> None:
        assert jwk.register_key("ALG", jwk.Key)
        assert jwk.get_key("ALG") == jwk.Key

        with pytest.raises(TypeError):
            assert jwk.register_key("ALG", object)
