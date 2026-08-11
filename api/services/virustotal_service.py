"""
VirusTotal Threat Intelligence Service
Submits URLs/domains to VirusTotal API v3 and returns vendor detection counts.
"""

import asyncio
import base64
import logging
import os
import re
from typing import Optional
import httpx

log = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 10.0


def _url_to_vt_id(url: str) -> str:
    """Convert URL string to VirusTotal base64 identifier."""
    raw = url.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "http://" + raw
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    return b64.rstrip("=")


def _extract_target(text: str) -> Optional[str]:
    """Extract first URL or bare domain from input text."""
    full_url = re.search(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
    if full_url:
        return full_url.group(0)

    domain = re.search(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|gov|edu|io|info|work|site|online|tech|app|xyz|top|live|me|co|in|ly)\b",
        text,
        re.IGNORECASE,
    )
    if domain:
        return f"https://{domain.group(0)}"

    return None


async def check_virustotal(target_input: str) -> dict:
    """
    Submits target to VirusTotal API v3 and retrieves analysis results.
    """
    fallback = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_vendors": 0,
        "vendors_flagged": [],
        "reputation": 0,
        "vt_risk_score": 5,
        "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        fallback["error"] = "VirusTotal API key not configured"
        return fallback

    target_url = _extract_target(target_input)
    if not target_url:
        fallback["error"] = "No valid URL or domain found for VirusTotal lookup"
        return fallback

    url_id = _url_to_vt_id(target_url)
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                results = attr.get("last_analysis_results", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values()) if stats else 0

                flagged = [
                    engine
                    for engine, r in results.items()
                    if r.get("category") in ("malicious", "suspicious")
                ]

                if malicious >= 5:
                    score = 85
                elif malicious >= 1:
                    score = 50
                elif suspicious >= 1:
                    score = 30
                else:
                    score = 5

                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total_vendors": total,
                    "vendors_flagged": flagged,
                    "reputation": attr.get("reputation", 0),
                    "vt_risk_score": score,
                    "error": None,
                }
    except Exception as exc:
        log.warning("[VT Exception]: %s", exc)
        fallback["error"] = f"VirusTotal lookup error: {exc}"

    return fallback
