from datetime import datetime, timezone
import os

from fastapi import APIRouter

router = APIRouter(prefix="/examples", tags=["examples"])


@router.get("/status")
async def example_status():
    return {
        "module": "example_routes",
        "status": "ok",
        "environment": os.environ.get("APP_ENV", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/deploy-checklist")
async def deploy_checklist():
    return {
        "title": "SecureShare Deployment Checklist",
        "steps": [
            "Set MONGO_URL, DB_NAME, SECRET_KEY, and CORS_ORIGINS.",
            "Run backend with uvicorn server:app --host 0.0.0.0 --port 8000.",
            "Build frontend with REACT_APP_BACKEND_URL and serve static files.",
            "Run a health probe against /api/health/db and /api/examples/status.",
        ],
    }
