from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth

app = FastAPI(
    title="ARGUS Security Intelligence API",
    description="Website Security Intelligence & DevSecOps Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "argus-backend",
        "version": "0.1.0",
    }
