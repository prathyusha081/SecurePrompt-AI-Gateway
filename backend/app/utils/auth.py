"""
Minimal auth dependency for local/demo use: a shared API key header.
Swap for full JWT+RBAC (see docs/roadmap) before any real deployment —
this is intentionally simple so the project runs out-of-the-box.
"""
from fastapi import Header, HTTPException, status
from app.config import settings


async def verify_api_key(x_api_key: str = Header(default="")):
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )
    return True
