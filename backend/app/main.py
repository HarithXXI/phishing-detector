import threading
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION, ALLOWED_ORIGINS
from app.routes.analyze import router as analyze_router
from app.routes.chat import router as chat_router
from app.routes.preview import router as preview_router

from fastapi.responses import FileResponse, JSONResponse

def _find_frontend_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "frontend",
        Path.cwd() / "frontend",
        Path.cwd().parent / "frontend",
        Path(__file__).resolve().parent.parent / "frontend",
    ]
    for c in candidates:
        if c.exists() and (c / "index.html").exists():
            return c
    return candidates[0]

FRONTEND_DIR = _find_frontend_dir()

def _prewarm_rag():
    try:
        from app.rag.retriever import get_retriever
        get_retriever()
    except Exception as e:
        print(f"[RAG Prewarm Warning] {e}")

def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(analyze_router)
    app.include_router(analyze_router, prefix="/api")
    app.include_router(chat_router)
    app.include_router(chat_router, prefix="/api")
    app.include_router(preview_router)
    app.include_router(preview_router, prefix="/api")

    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "ok"}

    index_html = FRONTEND_DIR / "index.html"
    if index_html.exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
    else:
        @app.get("/", tags=["Root"])
        async def root():
            return JSONResponse({
                "message": "PhishGuard AI Backend Active",
                "status": "online",
                "docs": "/docs",
                "health": "/health"
            })

    # Pre-warm RAG model in background so first user query is instant
    threading.Thread(target=_prewarm_rag, daemon=True).start()

    return app

app = create_app()
