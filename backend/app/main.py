from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.security_api import router as security_router
from backend.app.rate_limiter import limiter


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security-related HTTP response headers.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"

        response.headers["X-Frame-Options"] = "DENY"

        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; "
            "img-src 'self' data: "
            "https://fastapi.tiangolo.com; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'"
        )

        response.headers["Permissions-Policy"] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        return response


app = FastAPI(
    title="LLM-Sentinel",
    description="LLM Application Security Gateway",
    version="1.0.0",
)


app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


app.add_middleware(
    SecurityHeadersMiddleware
)


app.include_router(
    security_router
)


@app.get("/")
def root():
    return {
        "project": "LLM-Sentinel",
        "status": "online",
        "message": "LLM Security Gateway is running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "gateway": "online",
        "service": "LLM-Sentinel",
    }