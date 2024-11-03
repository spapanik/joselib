import os

import pytest
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from joselib.exceptions import DecryptionError, JWEError, JWKError
from joselib.jwa import (
    CONTENT_ENCRYPTION_ALGORITHMS,
    KEY_MANAGEMENT_ALGORITHMS,
    SIGNING_ALGORITHMS,
    CBCHMACEncryption,
)
from joselib.jwk import ECKey, Key, OctKey, OKPKey, RSAKey

_SIGNING_KEY_FIXTURES = {
    "HS256": "oct_key",
    "HS384": "oct_key",
    "HS512": "oct_key",
    "RS256": "rsa_key",
    "RS384": "rsa_key",
    "RS512": "rsa_key",
    "PS256": "rsa_key",
    "PS384": "rsa_key",
    "PS512": "rsa_key",
    "ES256": "ec_key",
    "ES384": "ec_key_p384",
    "ES512": "ec_key_p521",
    "EdDSA": "okp_key",
}


def test_registries_are_consistent() -> None:
    registries = (
        SIGNING_ALGORITHMS,
        KEY_MANAGEMENT_ALGORITHMS,
        CONTENT_ENCRYPTION_ALGORITHMS,
    )
    for registry in registries:
        assert all(name == algorithm.name for name, algorithm in registry.items())


class TestSigningAlgorithms:
    @pytest.mark.parametrize("name", sorted(SIGNING_ALGORITHMS))
    def test_sign_and_verify(self, name: str, request: pytest.FixtureRequest) -> None:
        key: Key = request.getfixturevalue(_SIGNING_KEY_FIXTURES[name])
        algorithm = SIGNING_ALGORITHMS[name]
        signature = algorithm.sign(key, b"data")
        assert algorithm.verify(key, b"data", signature)
        assert not algorithm.verify(key, b"other", signature)
        if not isinstance(key, OctKey):
            assert algorithm.verify(key.public(), b"data", signature)

    @pytest.mark.parametrize(
        ("name", "fixture"),
        [
            ("HS256", "rsa_key"),
            ("RS256", "oct_key"),
            ("PS256", "ec_key"),
            ("ES256", "okp_key"),
            ("EdDSA", "ec_key"),
        ],
    )
    def test_wrong_key_type(
        self, name: str, fixture: str, request: pytest.FixtureRequest
    ) -> None:
        key: Key = request.getfixturevalue(fixture)
        with pytest.raises(JWKError):
            SIGNING_ALGORITHMS[name].sign(key, b"data")

    def test_hmac_key_must_match_hash_size(self) -> None:
        with pytest.raises(JWKError):
            SIGNING_ALGORITHMS["HS256"].sign(OctKey.generate(16), b"data")

    def test_ec_curve_must_match(self, ec_key_p384: ECKey) -> None:
        with pytest.raises(JWKError):
            SIGNING_ALGORITHMS["ES256"].sign(ec_key_p384, b"data")

    def test_ec_rejects_wrong_signature_length(self, ec_key: ECKey) -> None:
        algorithm = SIGNING_ALGORITHMS["ES256"]
        signature = algorithm.sign(ec_key, b"data")
        assert not algorithm.verify(ec_key, b"data", signature + b"\x00")

    def test_sign_requires_private_key(self, okp_key: OKPKey) -> None:
        with pytest.raises(JWKError):
            SIGNING_ALGORITHMS["EdDSA"].sign(okp_key.public(), b"data")


class TestContentEncryption:
    @pytest.mark.parametrize("name", sorted(CONTENT_ENCRYPTION_ALGORITHMS))
    def test_round_trip(self, name: str) -> None:
        encryption = CONTENT_ENCRYPTION_ALGORITHMS[name]
        cek = encryption.generate_cek()
        assert len(cek) == encryption.key_size
        iv, ciphertext, tag = encryption.encrypt(cek, b"plaintext", b"aad")
        assert encryption.decrypt(cek, iv, ciphertext, tag, b"aad") == b"plaintext"

    @pytest.mark.parametrize("name", sorted(CONTENT_ENCRYPTION_ALGORITHMS))
    def test_tampering_is_detected(self, name: str) -> None:
        encryption = CONTENT_ENCRYPTION_ALGORITHMS[name]
        cek = encryption.generate_cek()
        iv, ciphertext, tag = encryption.encrypt(cek, b"plaintext", b"aad")
        bad_text = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv, bad_text, tag, b"aad")
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv, ciphertext, bad_tag, b"aad")
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv, ciphertext, tag, b"other aad")

    @pytest.mark.parametrize("name", ["A128GCM", "A128CBC-HS256"])
    def test_wrong_cek_size(self, name: str) -> None:
        encryption = CONTENT_ENCRYPTION_ALGORITHMS[name]
        cek = encryption.generate_cek()
        iv, ciphertext, tag = encryption.encrypt(cek, b"plaintext", b"")
        with pytest.raises(JWEError):
            encryption.encrypt(b"\x00" * 7, b"plaintext", b"")
        with pytest.raises(DecryptionError):
            encryption.decrypt(b"\x00" * 7, iv, ciphertext, tag, b"")
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv[:-1], ciphertext, tag, b"")

    def test_gcm_rejects_wrong_tag_size(self) -> None:
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A128GCM"]
        cek = encryption.generate_cek()
        iv, ciphertext, tag = encryption.encrypt(cek, b"plaintext", b"")
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv, ciphertext, tag[:-1], b"")

    @pytest.mark.parametrize("ciphertext", [b"", b"\x00" * 15])
    def test_cbc_rejects_misaligned_ciphertext(self, ciphertext: bytes) -> None:
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A128CBC-HS256"]
        cek = encryption.generate_cek()
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, b"\x00" * 16, ciphertext, b"\x00" * 16, b"")

    def test_cbc_rejects_invalid_padding(self) -> None:
        encryption = CBCHMACEncryption(128)
        cek, iv = bytes(32), bytes(16)
        encryptor = Cipher(algorithms.AES(cek[16:]), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(bytes(16)) + encryptor.finalize()
        tag = encryption._tag(cek[:16], iv, ciphertext, b"")
        with pytest.raises(DecryptionError):
            encryption.decrypt(cek, iv, ciphertext, tag, b"")


class TestKeyManagement:
    def test_direct(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["dir"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
        key = OctKey.generate(32)
        cek, encrypted_key = algorithm.encrypt_cek(key, encryption)
        assert cek == key.secret
        assert encrypted_key == b""
        assert algorithm.decrypt_cek(key, b"", encryption) == key.secret

    def test_direct_wrong_key_size(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["dir"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
        with pytest.raises(JWKError):
            algorithm.encrypt_cek(OctKey.generate(16), encryption)

    def test_direct_wrong_key_type(self, rsa_key: RSAKey) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["dir"]
        with pytest.raises(JWKError):
            algorithm.encrypt_cek(rsa_key, CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"])

    def test_direct_rejects_encrypted_key(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["dir"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(OctKey.generate(32), b"junk", encryption)

    @pytest.mark.parametrize("size", [128, 192, 256])
    def test_aeskw_round_trip(self, size: int) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS[f"A{size}KW"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A128GCM"]
        key = OctKey.generate(size // 8)
        cek, wrapped = algorithm.encrypt_cek(key, encryption)
        assert algorithm.decrypt_cek(key, wrapped, encryption) == cek

    def test_aeskw_wrong_secret_size(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["A128KW"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A128GCM"]
        with pytest.raises(JWKError):
            algorithm.encrypt_cek(OctKey.generate(32), encryption)

    def test_aeskw_tampered_key(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["A128KW"]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A128GCM"]
        key = OctKey.generate(16)
        _, wrapped = algorithm.encrypt_cek(key, encryption)
        bad = bytes([wrapped[0] ^ 1]) + wrapped[1:]
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(key, bad, encryption)
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(key, b"", encryption)

    def test_aeskw_cek_size_mismatch(self) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["A128KW"]
        key = OctKey.generate(16)
        wrapped = keywrap.aes_key_wrap(key.secret, os.urandom(16))
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(
                key, wrapped, CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
            )

    @pytest.mark.parametrize("name", ["RSA-OAEP", "RSA-OAEP-256"])
    def test_rsa_oaep_round_trip(self, name: str, rsa_key: RSAKey) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS[name]
        encryption = CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
        cek, wrapped = algorithm.encrypt_cek(rsa_key, encryption)
        assert algorithm.decrypt_cek(rsa_key, wrapped, encryption) == cek

    def test_rsa_oaep_garbage(self, rsa_key: RSAKey) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["RSA-OAEP"]
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(
                rsa_key, b"\x00" * 256, CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
            )

    def test_rsa_oaep_wrong_key_type(self, oct_key: OctKey) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["RSA-OAEP"]
        with pytest.raises(JWKError):
            algorithm.encrypt_cek(oct_key, CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"])

    def test_rsa_oaep_cek_size_mismatch(self, rsa_key: RSAKey) -> None:
        algorithm = KEY_MANAGEMENT_ALGORITHMS["RSA-OAEP"]
        oaep = padding.OAEP(
            # SHA-1 is what the RSA-OAEP JOSE algorithm identifier mandates.
            mgf=padding.MGF1(hashes.SHA1()),  # noqa: S303
            algorithm=hashes.SHA1(),  # noqa: S303
            label=None,
        )
        wrapped = rsa_key.crypto_public_key.encrypt(os.urandom(16), oaep)
        with pytest.raises(DecryptionError):
            algorithm.decrypt_cek(
                rsa_key, wrapped, CONTENT_ENCRYPTION_ALGORITHMS["A256GCM"]
            )
