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

# ── CORS Middleware ────────────────────────────────────────────────────────────
# Allows Vite frontend (localhost:5173 / 127.0.0.1:5173) to communicate with API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
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


# Include Routers
app.include_router(user_router)
app.include_router(guardian_router)
app.include_router(dashboard_router)
app.include_router(security_router)