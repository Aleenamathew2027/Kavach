from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.dashboard import router as dashboard_router
from app.api.guardian import router as guardian_router
from app.api.security import router as security_router
from app.api.user import router as user_router
from app.database.init_db import init_db

# Initialize database schema and ensure predefined admin account on startup
init_db()

app = FastAPI(
    title="Kavach API",
    description="KAVACH AI Digital Guardian Backend API with Role-Based Access Control (Admin, User, Guardian)",
    version="1.0.0"
)

import os

default_origins = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

env_cors = os.getenv("CORS_ORIGINS", "")
if env_cors:
    extra_origins = [origin.strip() for origin in env_cors.split(",") if origin.strip()]
    allowed_origins = list(dict.fromkeys(default_origins + extra_origins))
else:
    allowed_origins = default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ──────────────────────────────────────────────────────────────────────────────


@app.get("/", tags=["General"])
def home():
    return {
        "message": "Welcome to Kavach API"
    }


@app.get("/health", tags=["General"], summary="Safe System Health Check")
def health_check():
    """Returns system operational status and database connectivity safely without exposing secrets."""
    db_status = "connected"
    try:
        from sqlalchemy import text
        from app.database.connection import SessionLocal
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
    except Exception:
        db_status = "degraded"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "app_title": "Kavach API",
        "version": "1.0.0",
        "database": db_status,
        "environment": os.getenv("ENVIRONMENT", "development").lower(),
    }


from app.api.incident_reports import router as incident_reports_router

# Include Routers
app.include_router(user_router)
app.include_router(guardian_router)
app.include_router(dashboard_router)
app.include_router(security_router)
app.include_router(incident_reports_router)