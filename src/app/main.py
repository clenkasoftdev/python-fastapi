from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings
from .auth import (
    CognitoJWTVerifier,
    AuthError,
    TokenExpired,
    InvalidIssuer,
    InvalidAudience,
    PublicKeyNotFound,
    SignatureVerificationFailed,
)
from .schemas import TokenData

app = FastAPI(title="WelcomeToGermany - FastAPI + Cognito")

# Instantiate verifier once for the app lifetime
verifier = CognitoJWTVerifier(settings)

bearer = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> TokenData:
    token = credentials.credentials
    try:
        claims = verifier.verify(token)
    except TokenExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (InvalidAudience, InvalidIssuer, PublicKeyNotFound, SignatureVerificationFailed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except AuthError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception:
        # Unexpected error - surface as 500
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="internal error")
    username = claims.get('username') or claims.get('cognito:username')
    return TokenData(sub=claims.get('sub'), username=username)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/protected")
def protected(user: TokenData = Depends(get_current_user)) -> dict:
    return {"message": f"Hello, {user.username or user.sub}"}
