import time
from datetime import UTC, datetime, timedelta

import pytest

from joselib.exceptions import (
    DecodeError,
    ExpiredTokenError,
    InvalidClaimError,
    JWTError,
)
from joselib.jwk import OctKey
from joselib.jws import JWS
from joselib.jwt import JWT


@pytest.fixture
def jwt(oct_key: OctKey) -> JWT:
    return JWT(oct_key, "HS256")


class TestEncode:
    def test_round_trip(self, jwt: JWT) -> None:
        claims: dict[str, object] = {"sub": "user", "exp": int(time.time()) + 60}
        assert jwt.decode(jwt.encode(claims)) == claims

    def test_typ_header(self, jwt: JWT) -> None:
        token = jwt.encode({})
        assert JWS.unverified_header(token) == {"alg": "HS256", "typ": "JWT"}

    def test_extra_headers(self, jwt: JWT) -> None:
        token = jwt.encode({}, headers={"cty": "JWT"})
        header = JWS.unverified_header(token)
        assert header == {"alg": "HS256", "typ": "JWT", "cty": "JWT"}

    def test_datetime_claims(self, jwt: JWT) -> None:
        expiration = datetime.now(tz=UTC) + timedelta(minutes=1)
        claims = jwt.decode(jwt.encode({"exp": expiration}))
        assert claims["exp"] == int(expiration.timestamp())

    def test_naive_datetime_claims_are_rejected(self, jwt: JWT) -> None:
        with pytest.raises(JWTError):
            jwt.encode({"exp": datetime.now(tz=UTC).replace(tzinfo=None)})


class TestDecode:
    def test_expired_token(self, jwt: JWT, oct_key: OctKey) -> None:
        token = jwt.encode({"exp": int(time.time()) - 120})
        with pytest.raises(ExpiredTokenError):
            jwt.decode(token)
        lenient = JWT(oct_key, "HS256", leeway=300)
        assert "exp" in lenient.decode(token)

    @pytest.mark.parametrize("value", [True, "soon"])
    def test_exp_wrong_type(self, jwt: JWT, value: object) -> None:
        with pytest.raises(InvalidClaimError) as info:
            jwt.decode(jwt.encode({"exp": value}))
        assert info.value.claim == "exp"

    def test_nbf_in_the_future(self, jwt: JWT, oct_key: OctKey) -> None:
        token = jwt.encode({"nbf": int(time.time()) + 120})
        with pytest.raises(InvalidClaimError):
            jwt.decode(token)
        lenient = JWT(oct_key, "HS256", leeway=300)
        assert "nbf" in lenient.decode(token)

    def test_nbf_in_the_past(self, jwt: JWT) -> None:
        token = jwt.encode({"nbf": int(time.time()) - 120})
        assert "nbf" in jwt.decode(token)

    def test_iat_wrong_type(self, jwt: JWT) -> None:
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"iat": "yesterday"}))

    @pytest.mark.parametrize("claim", ["sub", "jti"])
    def test_string_claims_wrong_type(self, jwt: JWT, claim: str) -> None:
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({claim: 42}))

    def test_required_claims(self, oct_key: OctKey) -> None:
        jwt = JWT(oct_key, "HS256", required_claims={"exp", "sub"})
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"sub": "user"}))
        token = jwt.encode({"sub": "user", "exp": int(time.time()) + 60})
        assert jwt.decode(token)["sub"] == "user"

    def test_issuer_validation(self, oct_key: OctKey) -> None:
        jwt = JWT(oct_key, "HS256", issuer="me")
        assert jwt.decode(jwt.encode({"iss": "me"}))["iss"] == "me"
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"iss": "you"}))
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({}))

    def test_issuer_type_is_checked_even_when_not_expected(self, jwt: JWT) -> None:
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"iss": 42}))

    def test_issuer_ignored_when_not_expected(self, jwt: JWT) -> None:
        assert jwt.decode(jwt.encode({"iss": "me"}))["iss"] == "me"

    def test_audience_validation(self, oct_key: OctKey) -> None:
        jwt = JWT(oct_key, "HS256", audience="me")
        assert jwt.decode(jwt.encode({"aud": "me"}))["aud"] == "me"
        assert jwt.decode(jwt.encode({"aud": ["me", "you"]}))
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"aud": "you"}))
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"aud": ["you", "them"]}))
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({}))

    @pytest.mark.parametrize("value", [42, [42], {"aud": "me"}])
    def test_audience_wrong_type(self, oct_key: OctKey, value: object) -> None:
        jwt = JWT(oct_key, "HS256", audience="me")
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"aud": value}))

    def test_unexpected_audience(self, jwt: JWT) -> None:
        with pytest.raises(InvalidClaimError):
            jwt.decode(jwt.encode({"aud": "me"}))

    def test_claims_must_be_an_object(self, jwt: JWT, oct_key: OctKey) -> None:
        token = JWS(oct_key, "HS256").sign(b"[]")
        with pytest.raises(DecodeError):
            jwt.decode(token)
