"""Simple Cognito JWT verifier using python-jose and JWKS.

This implements a small in-memory cache for the JWKS and performs signature
and claims checks (iss, exp, aud). It's synchronous and intentionally
lightweight so it is easy to reason about and test.
"""
import time
import threading
from typing import Dict

import requests
from jose import jwk, jwt
from jose.utils import base64url_decode

from .config import settings


class CognitoJWTVerifier:
    def __init__(self, settings_obj=None, cache_ttl: int = 3600):
        # settings_obj is injected for easier testing; default to module settings
        self.settings = settings_obj or settings
        self._jwks = None
        self._last_update = 0.0
        self._lock = threading.Lock()
        self._cache_ttl = cache_ttl

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

        Raises Exception (or requests exceptions) on failure.
        """
        self._refresh_jwks()

        # find the key
        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid")
        key_index = -1
        for i, k in enumerate(self._jwks.get("keys", [])):
            if k.get("kid") == kid:
                key_index = i
                break
        if key_index == -1:
            raise Exception("Public key not found in JWKS")

        # Verify signature
        public_key = jwk.construct(self._jwks["keys"][key_index])
        message, encoded_sig = token.rsplit('.', 1)
        decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))
        if not public_key.verify(message.encode('utf-8'), decoded_sig):
            raise Exception("Signature verification failed")

        # Validate standard claims
        claims = jwt.get_unverified_claims(token)
        now = time.time()
        if now > claims.get('exp', 0):
            raise Exception("Token is expired")

        issuer = f"https://cognito-idp.{self.settings.region}.amazonaws.com/{self.settings.user_pool_id}"
        if claims.get('iss') != issuer:
            raise Exception("Invalid issuer")

        aud = claims.get('aud')
        if isinstance(aud, list):
            if self.settings.app_client_id not in aud:
                raise Exception("Invalid audience")
        else:
            if aud != self.settings.app_client_id:
                raise Exception("Invalid audience")

        return claims
