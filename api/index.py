import os
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PhishGuard v3.1 Vercel Proxy")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BACKEND_URL = os.getenv("BACKEND_URL", "https://phishing-detector.onrender.com").rstrip("/")


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy(path: str, request: Request):
    target = f"{BACKEND_URL}/api/{path}"
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length"]}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.request(
                method=request.method,
                url=target,
                params=dict(request.query_params),
                content=body,
                headers=headers
            )
            try:
                return JSONResponse(content=r.json(), status_code=r.status_code)
            except Exception:
                return JSONResponse(content={"data": r.text}, status_code=r.status_code)
        except Exception as e:
            return JSONResponse(
                content={"error": "Backend server connection timeout or unreachable", "details": str(e), "target": target},
                status_code=503
            )


@app.get("/api")
def health():
    return {"status": "v3.1 Vercel Proxy Active", "backend_url": BACKEND_URL}
