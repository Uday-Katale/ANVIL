"""
Central configuration for the Autonomous Red-Team Engine.
All secrets and environment toggles live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (one level above app/)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ── LLM Provider ──────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.0"))

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ── SQLite ────────────────────────────────────────────────────────────────────
SQLITE_DB_PATH: str = os.getenv("SQLITE_DB_PATH", "master_state.db")

# ── Celery ────────────────────────────────────────────────────────────────────
CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

# ── Sandbox ───────────────────────────────────────────────────────────────────
SANDBOX_TIMEOUT_SECONDS: int = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "15"))
SANDBOX_MAX_RETRIES: int = int(os.getenv("SANDBOX_MAX_RETRIES", "3"))

# ── Omium / OpenTelemetry ─────────────────────────────────────────────────────
OMIUM_API_KEY: str = os.getenv("OMIUM_API_KEY", "")
OMIUM_ENDPOINT: str = os.getenv(
    "OMIUM_ENDPOINT",
    "https://api.omium.ai",
)
SERVICE_NAME: str = os.getenv("SERVICE_NAME", "red-team-engine")

# ── Target Application ────────────────────────────────────────────────────────
TARGET_APP_HOST: str = os.getenv("TARGET_APP_HOST", "http://localhost:9999")
TARGET_REPO_DIR: str = os.getenv("TARGET_REPO_DIR", "target_app")

# ── Redis Streams ─────────────────────────────────────────────────────────────
REDIS_TASK_STREAM: str = "agent:tasks"
REDIS_RESULT_STREAM: str = "agent:results"
REDIS_CONSUMER_GROUP: str = "orchestrator-group"

# ── GitHub OAuth ──────────────────────────────────────────────────────────────
GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI: str = os.getenv(
    "GITHUB_REDIRECT_URI", "http://localhost:8000/api/auth/callback"
)

# ── Session / Security ───────────────────────────────────────────────────────
SESSION_SECRET: str = os.getenv("SESSION_SECRET", "change-me-in-production-32bytes!")

# ── Scan Workspace ───────────────────────────────────────────────────────────
SCAN_TEMP_DIR: str = os.getenv("SCAN_TEMP_DIR", str(Path(__file__).resolve().parent.parent / "scans"))
