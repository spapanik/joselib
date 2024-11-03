import pytest

from joselib.exceptions import (
    DecodeError,
    InvalidSignatureError,
    JWSError,
    UnsupportedAlgorithmError,
)
from joselib.jwk import Key, OctKey
from joselib.jws import JWS
from joselib.utils import b64url_encode, json_encode

# The JWS example from RFC 7515, appendix A.1.
RFC_7515_JWS = (
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
RFC_7515_JWK = {
    "kty": "oct",
    "k": (
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
        "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    ),
}


def craft_token(
    header: dict[str, object], payload: bytes = b"x", signature: bytes = b"\x00" * 32
) -> str:
    segments = (
        b64url_encode(json_encode(header)),
        b64url_encode(payload),
        b64url_encode(signature),
    )
    return b".".join(segments).decode()


class TestJWS:
    def test_round_trip(self, oct_key: OctKey) -> None:
        jws = JWS(oct_key, "HS256")
        token = jws.sign(b"payload")
        assert jws.verify(token) == b"payload"
        assert jws.verify(token.encode()) == b"payload"

    def test_verification_with_public_key(self, ec_key: Key) -> None:
        token = JWS(ec_key, "ES256").sign(b"payload")
        assert JWS(ec_key.public(), "ES256").verify(token) == b"payload"

    def test_kid_header(self) -> None:
        key = OctKey(b"\x00" * 32, kid="a-kid")
        token = JWS(key, "HS256").sign(b"payload")
        assert JWS.unverified_header(token) == {"alg": "HS256", "kid": "a-kid"}

    def test_custom_headers_at_init(self, oct_key: OctKey) -> None:
        jws = JWS(oct_key, "HS256", headers={"cty": "text/plain"})
        header = JWS.unverified_header(jws.sign(b"payload"))
        assert header == {"alg": "HS256", "cty": "text/plain"}

    def test_custom_headers_at_sign(self, oct_key: OctKey) -> None:
        jws = JWS(oct_key, "HS256")
        token = jws.sign(b"payload", headers={"cty": "text/plain"})
        assert JWS.unverified_header(token) == {"alg": "HS256", "cty": "text/plain"}
        assert jws.verify(token) == b"payload"

    @pytest.mark.parametrize("field", ["alg", "crit"])
    def test_reserved_headers(self, oct_key: OctKey, field: str) -> None:
        jws = JWS(oct_key, "HS256")
        with pytest.raises(JWSError):
            jws.sign(b"payload", headers={field: "HS384"})
        with pytest.raises(JWSError):
            JWS(oct_key, "HS256", headers={field: "HS384"})

    def test_unknown_algorithm(self, oct_key: OctKey) -> None:
        with pytest.raises(UnsupportedAlgorithmError) as info:
            JWS(oct_key, "XS256")
        assert info.value.algorithm == "XS256"

    def test_none_algorithm_cannot_be_used(self, oct_key: OctKey) -> None:
        with pytest.raises(UnsupportedAlgorithmError):
            JWS(oct_key, "none")

    def test_unknown_allowed_algorithm(self, oct_key: OctKey) -> None:
        with pytest.raises(UnsupportedAlgorithmError):
            JWS(oct_key, "HS256", allowed_algorithms={"HS256", "none"})

    def test_allowed_algorithms_verification(self, oct_key: OctKey) -> None:
        token = JWS(oct_key, "HS384").sign(b"payload")
        verifier = JWS(oct_key, "HS256", allowed_algorithms={"HS256", "HS384"})
        assert verifier.verify(token) == b"payload"

    def test_rejects_algorithm_not_in_allowlist(self, oct_key: OctKey) -> None:
        token = JWS(oct_key, "HS384").sign(b"payload")
        with pytest.raises(UnsupportedAlgorithmError):
            JWS(oct_key, "HS256").verify(token)

    def test_rejects_none_token(self, oct_key: OctKey) -> None:
        token = craft_token({"alg": "none"}, signature=b"")
        with pytest.raises(UnsupportedAlgorithmError):
            JWS(oct_key, "HS256").verify(token)

    def test_rejects_non_string_alg(self, oct_key: OctKey) -> None:
        token = craft_token({"alg": 42})
        with pytest.raises(UnsupportedAlgorithmError):
            JWS(oct_key, "HS256").verify(token)

    def test_rejects_critical_headers(self, oct_key: OctKey) -> None:
        token = craft_token({"alg": "HS256", "crit": ["exp"], "exp": 0})
        with pytest.raises(JWSError):
            JWS(oct_key, "HS256").verify(token)

    @pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d"])
    def test_rejects_wrong_segment_count(self, oct_key: OctKey, token: str) -> None:
        with pytest.raises(JWSError):
            JWS(oct_key, "HS256").verify(token)

    def test_rejects_malformed_header(self, oct_key: OctKey) -> None:
        with pytest.raises(DecodeError):
            JWS(oct_key, "HS256").verify("?.b.c")

    def test_rejects_tampered_payload(self, oct_key: OctKey) -> None:
        jws = JWS(oct_key, "HS256")
        header, _, signature = jws.sign(b"payload").split(".")
        payload = b64url_encode(b"other").decode()
        with pytest.raises(InvalidSignatureError):
            jws.verify(f"{header}.{payload}.{signature}")

    def test_rejects_wrong_key(self, oct_key: OctKey) -> None:
        token = JWS(oct_key, "HS256").sign(b"payload")
        with pytest.raises(InvalidSignatureError):
            JWS(OctKey.generate(), "HS256").verify(token)

    def test_unverified_header(self, oct_key: OctKey) -> None:
        token = JWS(oct_key, "HS256").sign(b"payload")
        assert JWS.unverified_header(token) == {"alg": "HS256"}
        assert JWS.unverified_header(token.encode()) == {"alg": "HS256"}

    def test_rfc_7515_hs256_vector(self) -> None:
        key = OctKey.from_jwk(RFC_7515_JWK)
        payload = JWS(key, "HS256").verify(RFC_7515_JWS)
        assert b'"iss":"joe"' in payload
