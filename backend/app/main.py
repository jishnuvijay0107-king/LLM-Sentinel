from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.security_api import router as security_router
from backend.app.rate_limiter import limiter
from backend.app.workspace_api import router as workspace_router


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
app.include_router(workspace_router)

WEB_ROOT = Path(__file__).resolve().parents[2] / "dashboard" / "web"
app.mount("/assets", StaticFiles(directory=WEB_ROOT), name="assets")


@app.get("/")
def root():
    return FileResponse(WEB_ROOT / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "gateway": "online",
        "service": "LLM-Sentinel",
    }
