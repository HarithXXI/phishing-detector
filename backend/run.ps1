# PhishGuard AI — Fast Dev Server Startup
# Watches only app/ directory so reload is instant (<2s) and ignores vector_store/data

.\venv\Scripts\python.exe -m uvicorn app.main:app --reload --reload-dir app --port 8000
