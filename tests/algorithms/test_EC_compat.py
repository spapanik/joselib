from joselib.constants import ALGORITHMS
from joselib.keys import ECKey

from tests.algorithms.test_EC import private_key


class TestBackendEcdsaCompatibility:
    def test_signing_parity(self):
        key_sign = ECKey(private_key, ALGORITHMS.ES256)
        key_verify = ECKey(private_key, ALGORITHMS.ES256).public_key()

        msg = b"test"
        sig = key_sign.sign(msg)

        # valid signature
        assert key_verify.verify(msg, sig)

        # invalid signature
        assert not key_verify.verify(msg, b"n" * 64)

    def test_public_key_to_pem(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        key2 = ECKey(private_key, ALGORITHMS.ES256)

        assert key.public_key().to_pem().strip() == key2.public_key().to_pem().strip()

    def test_private_key_to_pem(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        key2 = ECKey(private_key, ALGORITHMS.ES256)

        assert key.to_pem().strip() == key2.to_pem().strip()

    def test_public_key_load_cycle(self):
        key = ECKey(private_key, ALGORITHMS.ES256)
        pubkey = key.public_key()

        pub_pem_source = pubkey.to_pem().strip()

        pub_target = ECKey(pub_pem_source, ALGORITHMS.ES256)

        assert pub_pem_source == pub_target.to_pem().strip()

    def test_private_key_load_cycle(self):
        key = ECKey(private_key, ALGORITHMS.ES256)

        pem_source = key.to_pem().strip()

        target = ECKey(pem_source, ALGORITHMS.ES256)

        assert pem_source == target.to_pem().strip()
