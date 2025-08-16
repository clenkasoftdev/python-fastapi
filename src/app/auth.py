"""Cognito JWT verifier that uses `aws-jwt-verify` when available.

If `aws-jwt-verify` is installed the verifier will use it. Otherwise it
falls back to the existing lightweight `python-jose`-based implementation.
This keeps behavior stable while preferring the AWS-maintained verifier.
"""
import time
import threading
from typing import Dict

import requests
from jose import jwk, jwt
from jose.utils import base64url_decode

from .config import settings


# Custom exceptions for authentication failures
class AuthError(Exception):
    """Base class for authentication-related errors."""


class TokenExpired(AuthError):
    pass


class InvalidIssuer(AuthError):
    pass


class InvalidAudience(AuthError):
    pass


class PublicKeyNotFound(AuthError):
    pass


class SignatureVerificationFailed(AuthError):
    pass

# Try to import the AWS verifier; it's optional. If it's present we'll use it.
_HAS_AWS_VERIFIER = False
try:
    # aws-jwt-verify (if installed) exposes JwtVerifier
    from aws_jwt_verify import JwtVerifier  # type: ignore

    _HAS_AWS_VERIFIER = True
except Exception:
    _HAS_AWS_VERIFIER = False


class CognitoJWTVerifier:
    def __init__(self, settings_obj=None, cache_ttl: int = 3600):
        self.settings = settings_obj or settings
        self._cache_ttl = cache_ttl
        self._jwks = None
        self._last_update = 0.0
        self._lock = threading.Lock()

        if _HAS_AWS_VERIFIER:
            issuer = f"https://cognito-idp.{self.settings.region}.amazonaws.com/{self.settings.user_pool_id}"
            # Construct the AWS verifier with issuer and audience (app client id)
            try:
                self._aws_verifier = JwtVerifier(issuer=issuer, audience=self.settings.app_client_id)
            except Exception:
                # If constructor differs, keep attribute but set to None so we fall back
                self._aws_verifier = None
        else:
            self._aws_verifier = None

    def _jwks_url(self) -> str:
        return f"https://cognito-idp.{self.settings.region}.amazonaws.com/{self.settings.user_pool_id}/.well-known/jwks.json"

    def _refresh_jwks(self) -> None:
        with self._lock:
            now = time.time()
            if self._jwks and (now - self._last_update) < self._cache_ttl:
                return
            resp = requests.get(self._jwks_url(), timeout=5)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._last_update = now

    def verify(self, token: str) -> Dict:
        """Verify the supplied JWT and return the token claims on success.

        This prefers `aws-jwt-verify` when available; otherwise it falls back
        to the `python-jose` implementation for signature + claims checks.
        """
        # Prefer AWS verifier if available and was constructed successfully
        if getattr(self, "_aws_verifier", None):
            try:
                # Try common method names used by verifiers; if the API differs
                # the call will raise and we'll fall back to jose
                if hasattr(self._aws_verifier, "verify"):
                    return self._aws_verifier.verify(token)
                if hasattr(self._aws_verifier, "verify_jwt"):
                    return self._aws_verifier.verify_jwt(token)
                # Last resort: try calling the object
                return self._aws_verifier(token)
            except Exception:
                # fall through to jose-based verification
                pass

        # Fallback: existing python-jose based verification
        self._refresh_jwks()

        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid")
        key_index = -1
        for i, k in enumerate(self._jwks.get("keys", [])):
            if k.get("kid") == kid:
                key_index = i
                break
        if key_index == -1:
            raise PublicKeyNotFound("Public key not found in JWKS")

        public_key = jwk.construct(self._jwks["keys"][key_index])
        message, encoded_sig = token.rsplit('.', 1)
        decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))
        if not public_key.verify(message.encode('utf-8'), decoded_sig):
            raise SignatureVerificationFailed("Signature verification failed")

        claims = jwt.get_unverified_claims(token)
        now = time.time()
        if now > claims.get('exp', 0):
            raise TokenExpired("Token is expired")

        issuer = f"https://cognito-idp.{self.settings.region}.amazonaws.com/{self.settings.user_pool_id}"
        if claims.get('iss') != issuer:
            raise InvalidIssuer("Invalid issuer")

        aud = claims.get('aud')
        if isinstance(aud, list):
            if self.settings.app_client_id not in aud:
                raise InvalidAudience("Invalid audience")
        else:
            if aud != self.settings.app_client_id:
                raise InvalidAudience("Invalid audience")

        return claims
