import time
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt
from jose.utils import base64url_encode

import pytest

from src.app.auth import CognitoJWTVerifier, TokenExpired, PublicKeyNotFound, InvalidAudience


def generate_rsa_jwk_and_pem(kid: str):
    # Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()
    n = pub_numbers.n
    e = pub_numbers.e
    n_b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_b = e.to_bytes((e.bit_length() + 7) // 8, "big")
    n_b64 = base64url_encode(n_b).decode("utf-8")
    e_b64 = base64url_encode(e_b).decode("utf-8")

    jwk = {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n_b64, "e": e_b64}
    jwks = {"keys": [jwk]}
    return private_pem, jwks


def test_cognito_jwt_verifier_happy_path():
    kid = "test-kid"
    private_pem, jwks = generate_rsa_jwk_and_pem(kid)

    # Create settings-like object to inject
    region = "us-east-1"
    user_pool_id = "us-east-1_TEST"
    app_client_id = "client-id-123"
    settings_obj = SimpleNamespace(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    now = int(time.time())
    claims = {"sub": "user-1", "username": "tester", "iss": issuer, "aud": app_client_id, "exp": now + 300}

    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})

    class DummyResp:
        def raise_for_status(self):
            return None

        def json(self):
            return jwks

    verifier = CognitoJWTVerifier(settings_obj=settings_obj, cache_ttl=1)

    with patch("requests.get", return_value=DummyResp()):
        out_claims = verifier.verify(token)

    assert out_claims["sub"] == "user-1"
    assert out_claims["username"] == "tester"
    assert out_claims["iss"] == issuer
    assert out_claims["aud"] == app_client_id


def test_cognito_jwt_verifier_expired_token():
    kid = "expired-kid"
    private_pem, jwks = generate_rsa_jwk_and_pem(kid)

    region = "us-east-1"
    user_pool_id = "us-east-1_TEST"
    app_client_id = "client-id-123"
    settings_obj = SimpleNamespace(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    now = int(time.time())
    # expired
    claims = {"sub": "user-1", "username": "tester", "iss": issuer, "aud": app_client_id, "exp": now - 10}

    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})

    class DummyResp2:
        def raise_for_status(self):
            return None

        def json(self):
            return jwks

    verifier = CognitoJWTVerifier(settings_obj=settings_obj, cache_ttl=1)

    with patch("requests.get", return_value=DummyResp2()):
        with pytest.raises(TokenExpired):
            verifier.verify(token)


def test_cognito_jwt_verifier_wrong_kid():
    # Sign with kid A, but JWKS contains kid B
    sign_kid = "sign-kid"
    jwks_kid = "other-kid"
    private_pem, _ = generate_rsa_jwk_and_pem(sign_kid)

    # create a JWKS that does not include sign_kid
    _, jwks_for_resp = generate_rsa_jwk_and_pem(jwks_kid)

    region = "us-east-1"
    user_pool_id = "us-east-1_TEST"
    app_client_id = "client-id-123"
    settings_obj = SimpleNamespace(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    now = int(time.time())
    claims = {"sub": "user-1", "username": "tester", "iss": issuer, "aud": app_client_id, "exp": now + 300}

    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": sign_kid})

    class DummyResp3:
        def raise_for_status(self):
            return None

        def json(self):
            return jwks_for_resp

    verifier = CognitoJWTVerifier(settings_obj=settings_obj, cache_ttl=1)

    with patch("requests.get", return_value=DummyResp3()):
        with pytest.raises(PublicKeyNotFound):
            verifier.verify(token)


def test_cognito_jwt_verifier_wrong_audience():
    kid = "aud-kid"
    private_pem, jwks = generate_rsa_jwk_and_pem(kid)

    region = "us-east-1"
    user_pool_id = "us-east-1_TEST"
    app_client_id = "client-id-123"
    settings_obj = SimpleNamespace(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)

    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
    now = int(time.time())
    # audience does not match settings_obj.app_client_id
    claims = {"sub": "user-1", "username": "tester", "iss": issuer, "aud": "different-aud", "exp": now + 300}

    token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})

    class DummyResp4:
        def raise_for_status(self):
            return None

        def json(self):
            return jwks

    verifier = CognitoJWTVerifier(settings_obj=settings_obj, cache_ttl=1)

    with patch("requests.get", return_value=DummyResp4()):
        with pytest.raises(InvalidAudience):
            verifier.verify(token)
