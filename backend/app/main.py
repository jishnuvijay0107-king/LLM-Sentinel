from fastapi import FastAPI

from backend.app.security_api import router as security_router


app = FastAPI(
    title="LLM-Sentinel",
    description="LLM Application Security Gateway",
    version="1.0.0"
)


app.include_router(security_router)


@app.get("/")
def root():
    return {
        "project": "LLM-Sentinel",
        "status": "online",
        "message": "LLM Security Gateway is running"
    }