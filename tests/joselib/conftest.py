import pytest

from joselib.jwk import ECKey, OctKey, OKPKey, RSAKey


@pytest.fixture(scope="session")
def rsa_key() -> RSAKey:
    return RSAKey.generate()


@pytest.fixture(scope="session")
def ec_key() -> ECKey:
    return ECKey.generate()


@pytest.fixture(scope="session")
def ec_key_p384() -> ECKey:
    return ECKey.generate("P-384")


@pytest.fixture(scope="session")
def ec_key_p521() -> ECKey:
    return ECKey.generate("P-521")


@pytest.fixture(scope="session")
def okp_key() -> OKPKey:
    return OKPKey.generate()


@pytest.fixture(scope="session")
def oct_key() -> OctKey:
    return OctKey.generate(64)
