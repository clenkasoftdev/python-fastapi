# CI status

![CI](https://github.com/clenkasoftdev/python-fastapi/actions/workflows/ci.yml/badge.svg)

# FastAPI + Cognito example

This repository contains a minimal FastAPI application that verifies AWS Cognito JWTs using the JWKS endpoint and pydantic settings.

Quick start (Windows, bash.exe):

1. Copy the example env and fill in your Cognito values:

```bash
cp .env.example .env
# edit .env and set the right values
```

2. Create and activate a virtual environment, install deps:

```bash
python -m venv .venv
source .venv/Scripts/activate   # on Git Bash / Windows, use this path
pip install -r requirements.txt
```

3. Run the app with uvicorn:

```bash
uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000
```

Endpoints:

- GET /health — no auth
- GET /protected — requires a valid Cognito access or ID token in Authorization: Bearer <token>

Notes:

- Settings are loaded via pydantic BaseSettings from `.env` (see `src/app/config.py`).
- JWKS are cached in-memory for 1 hour. Adjust `cache_ttl` in `CognitoJWTVerifier` if needed.
