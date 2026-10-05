"""NETPHISH — Network Threat & Phishing Analysis Platform.

FastAPI main application entrypoint with modular REST API endpoints,
CORS security middleware, and dark SOC investigation UI mounting.

Author: Hrudyansh Kayastha
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import (
    APP_NAME,
    APP_DESCRIPTION,
    APP_VERSION,
    UI_STATIC_DIR,
    UI_TEMPLATES_DIR,
    SAMPLES_DIR,
)
from app.database import init_db
from app.api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes SQLite database schema on startup."""
    init_db()
    yield


# Ensure tables are created on module import (for test runners and ASGI servers)
init_db()

app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for local security workbench access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register REST API Router
app.include_router(router)

# Mount static asset directory if it exists
if UI_STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_STATIC_DIR)), name="static")

# Mount synthetic PCAP and URL samples directory
if SAMPLES_DIR.exists():
    app.mount("/samples", StaticFiles(directory=str(SAMPLES_DIR)), name="samples")


@app.get("/", include_in_schema=False)
def serve_index():
    """Serves the primary SOC Investigation Dashboard single-page application."""
    index_file = UI_TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": f"{APP_NAME} API Operational. Visit /docs for OpenAPI interface."}
