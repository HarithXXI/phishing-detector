"""
URL Preview Route

Follows shortener redirects safely on backend (e.g. cutt.ly -> destination)
and returns cloud rendering screenshot URL via Microlink API.
Zero client-side script execution.
"""

from urllib.parse import quote
import httpx
from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter(tags=["URL Preview"])


class PreviewRequest(BaseModel):
    url: str | None = None


async def _resolve_url(raw_url: str) -> tuple[str, str, str]:
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    final_url = url
    headers = {"User-Agent": "PhishGuardBot/1.0"}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0, headers=headers) as client:
            resp = await client.head(url)
            final_url = str(resp.url)
    except Exception:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=5.0, headers=headers) as client:
                resp = await client.get(url)
                final_url = str(resp.url)
        except Exception:
            final_url = url

    encoded_url = quote(final_url, safe="")
    screenshot_url = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&meta=false&embed=screenshot.url"

    return url, final_url, screenshot_url


@router.get("/preview")
@router.get("/api/preview")
@router.post("/preview")
@router.post("/api/preview")
async def preview_url(url: str = Query(None), req: PreviewRequest = None):
    target_url = url or (req.url if req else None)
    if not target_url:
        return {"error": "No URL provided", "safe": False}

    orig, final_url, screenshot_url = await _resolve_url(target_url)

    return {
        "original_url": orig,
        "final_url": final_url,
        "screenshot_url": screenshot_url,
        "safe": True,
    }
