"""
backend/app/auth_jwt.py

Yeh helper FastAPI scanner k liye JWT token validate karta hai.
Same secret use karta hai jo Flask auth (.env ka JWT_SECRET_KEY).
Frontend Authorization: Bearer <token> header bhejta hai, hum yahan
decode kar k user_id nikaaltay hain.
"""

import os
import logging
from typing import Optional

import jwt
from fastapi import Header, HTTPException, status
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("webxguard.auth_jwt")

# Same secret jo Flask app/config.py use kar raha hai
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-prod")
JWT_ALGORITHM  = "HS256"


def decode_token(token: str) -> Optional[int]:
    """
    Token decode karke user_id (int) return karta hai.
    Invalid / expired hua to None.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            return None
        # flask-jwt-extended kabhi int aur kabhi str rakhta hai
        return int(sub)
    except jwt.ExpiredSignatureError:
        logger.info("[JWT] Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"[JWT] Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"[JWT] Decode error: {e}")
        return None


# FastAPI dependency - har protected endpoint me Depends(get_current_user_id) lagao
async def get_current_user_id(
    authorization: Optional[str] = Header(None),
) -> int:
    """
    Authorization header se "Bearer <token>" parse karta hai.
    Token valid ho to user_id return, warna 401 throw.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    token   = parts[1]
    user_id = decode_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return user_id


# Optional version (token na ho to None return, throw nahi)
async def get_current_user_id_optional(
    authorization: Optional[str] = Header(None),
) -> Optional[int]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return decode_token(parts[1])