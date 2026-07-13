"""
SecurePrompt AI Gateway — FastAPI entrypoint.
Run with: uvicorn app.main:app --reload --port 8000
"""
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.database import init_db
from app.api.routes import router as api_router

app = FastAPI(
    title=settings.APP_NAME,
    description="Zero-Trust AI Gateway: inspects prompts and attachments for PII/PHI, "
                 "secrets, prompt injection, and jailbreak attempts before they reach any LLM.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Simple in-memory per-IP rate limiter for public demo deployments ---
# Deliberately dependency-free: a deque of request timestamps per IP,
# pruned to a rolling 60s window. Good enough for a single-instance free-tier
# demo; swap for Redis-backed rate limiting (see docs/ARCHITECTURE.md) if you
# scale to multiple instances.
_request_log: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if settings.DEMO_MODE and request.url.path.startswith("/api/"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = _request_log[client_ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= settings.RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded ({settings.RATE_LIMIT_PER_MINUTE}/min) on this public demo. Please wait a moment."},
            )
        window.append(now)
    return await call_next(request)


app.include_router(api_router, prefix="/api")


@app.on_event("startup")
async def on_startup():
    init_db()


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "status": "running",
        "docs": "/docs",
    }
