from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.app.main import app
from src.app.auth import (
    TokenExpired,
    InvalidAudience,
    InvalidIssuer,
    PublicKeyNotFound,
    SignatureVerificationFailed,
    AuthError,
)


client = TestClient(app)


def auth_headers():
    return {"Authorization": "Bearer dummy-token"}


def test_protected_token_expired():
    with patch("src.app.main.verifier.verify", side_effect=TokenExpired()):
        r = client.get("/protected", headers=auth_headers())
    assert r.status_code == 401
    assert r.json().get("detail") == "token expired"
    assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("exc", [InvalidAudience, InvalidIssuer, PublicKeyNotFound, SignatureVerificationFailed])
def test_protected_invalid_token_types(exc):
    with patch("src.app.main.verifier.verify", side_effect=exc()):
        r = client.get("/protected", headers=auth_headers())
    assert r.status_code == 401
    assert r.json().get("detail") == "invalid authentication token"
    assert r.headers.get("www-authenticate") == "Bearer"


def test_protected_generic_auth_error():
    with patch("src.app.main.verifier.verify", side_effect=AuthError()):
        r = client.get("/protected", headers=auth_headers())
    assert r.status_code == 401
    assert r.json().get("detail") == "authentication failed"
    assert r.headers.get("www-authenticate") == "Bearer"
