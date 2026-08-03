import threading
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION, ALLOWED_ORIGINS
from app.routes.analyze import router as analyze_router
from app.routes.chat import router as chat_router
from app.routes.preview import router as preview_router

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

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

    if FRONTEND_DIR.exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    # Pre-warm RAG model in background so first user query is instant
    threading.Thread(target=_prewarm_rag, daemon=True).start()

    return app

app = create_app()
