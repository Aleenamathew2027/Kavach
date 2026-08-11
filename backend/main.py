from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.user import router as user_router
from app.database.base import Base
from app.database.connection import engine
import app.models.user  # registers User model with Base

# Automatically create tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Kavach API")

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow the Vite dev server (http://127.0.0.1:5173 and http://localhost:5173) to call the API.
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


@app.get("/")
def home():
    return {
        "message": "Welcome to Kavach API"
    }


app.include_router(user_router)