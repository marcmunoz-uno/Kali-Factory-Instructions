"""Bearer-token auth for the Kali Factory API.

Token is loaded once at process startup from KALI_FACTORY_API_TOKEN_FILE.
Same pattern as GPU Factory — token in .secrets/api_token, env var points
at the file, file is permission-locked at 0600 by bootstrap-secrets.sh.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Header, HTTPException, status

_TOKEN_CACHE: str | None = None


def _load_token() -> str:
    global _TOKEN_CACHE
    if _TOKEN_CACHE is not None:
        return _TOKEN_CACHE

    token_file = os.environ.get("KALI_FACTORY_API_TOKEN_FILE")
    if not token_file:
        raise RuntimeError(
            "KALI_FACTORY_API_TOKEN_FILE not set. "
            "Run scripts/bootstrap-secrets.sh and source .env first."
        )

    path = Path(token_file)
    if not path.exists():
        raise RuntimeError(f"Token file not found: {token_file}")

    # Refuse to load tokens from world-readable files
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError(
            f"Token file {token_file} has insecure permissions ({oct(mode)}). "
            "Run: chmod 0600 {token_file}"
        )

    token = path.read_text().strip()
    if len(token) < 32:
        raise RuntimeError(
            "Token is shorter than 32 chars; refusing to start. "
            "Run scripts/bootstrap-secrets.sh to regenerate."
        )

    _TOKEN_CACHE = token
    return token


async def verify_bearer_token(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency that rejects any request without a valid bearer token."""
    expected = _load_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[len("Bearer "):]
    # Constant-time comparison
    if not secrets.compare_digest(presented.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
