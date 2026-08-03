"""
VirusTotal Threat Intelligence Service

Submits URLs/domains to VirusTotal API v3, polls for results,
and returns vendor detection counts with composite risk scoring.

Risk tiers:
  malicious >= 5  → 85
  malicious 1-4   → 50
  suspicious > 0  → 30
  else            →  5

API docs: https://docs.virustotal.com/reference/overview
"""

import asyncio
import base64
import logging
import re
from typing import Optional
import httpx

from app.config import VIRUSTOTAL_API_KEY

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
VT_BASE_URL      = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT  = 15.0          # seconds per request
POLL_ATTEMPTS    = 6             # max poll iterations after submission
POLL_INTERVAL    = 2.0           # seconds between polls

# ── Helpers ────────────────────────────────────────────────────────────────

def _extract_target(text: str) -> Optional[str]:
    """
    Return the first URL or bare domain found in *text*.
    Priority: full URL  >  bare domain (e.g. paypal.com).
    """
    url_match = re.search(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
    if url_match:
        return url_match.group(0).rstrip("/.,;")

    domain_match = re.search(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
        text,
        re.IGNORECASE,
    )
    if domain_match:
        return f"https://{domain_match.group(0)}"

    return None


def _url_id(url: str) -> str:
    """Base-64 URL-safe encode (no padding) for VT URL lookup."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _risk_score(malicious: int, suspicious: int) -> int:
    """Convert VT counts to a 0-100 risk integer per spec."""
    if malicious >= 5:
        return 85
    if malicious >= 1:
        return 50
    if suspicious > 0:
        return 30
    return 5


def _parse_attrs(attrs: dict) -> dict:
    """
    Extract the fields we care about from a VT attributes block.
    Works for both /urls/{id} (last_analysis_*) and /analyses/{id} (stats/results).
    """
    stats: dict = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    vendor_map: dict = (
        attrs.get("last_analysis_results") or attrs.get("results") or {}
    )

    malicious:  int = stats.get("malicious",  0)
    suspicious: int = stats.get("suspicious", 0)
    harmless:   int = stats.get("harmless",   0)
    undetected: int = stats.get("undetected", 0)
    total_vendors: int = malicious + suspicious + harmless + undetected

    vendors_flagged: list[str] = [
        vendor
        for vendor, info in vendor_map.items()
        if isinstance(info, dict)
        and info.get("category") in ("malicious", "suspicious")
    ]

    reputation: int = attrs.get("reputation", 0)

    risk = _risk_score(malicious, suspicious)

    return {
        "malicious":       malicious,
        "suspicious":      suspicious,
        "harmless":        harmless,
        "total_vendors":   total_vendors,
        "vendors_flagged": vendors_flagged,
        "reputation":      reputation,
        "vt_risk_score":   risk,
        "error":           None,
    }


# ── Public API ─────────────────────────────────────────────────────────────

async def check_virustotal(target: str) -> dict:
    """
    Submit *target* (URL or domain) to VirusTotal and return parsed stats.
    Performs real-time live queries directly against VirusTotal v3 API.
    """
    _empty = {
        "malicious": 0, "suspicious": 0, "harmless": 0,
        "total_vendors": 0, "vendors_flagged": [], "reputation": 0,
        "vt_risk_score": 5, "error": None,
    }

    if not VIRUSTOTAL_API_KEY:
        log.warning("[VT] API key not configured – skipping")
        return {**_empty, "error": "VirusTotal API key not configured"}

    url = _extract_target(target) or target
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/1.0",
        "Accept": "application/json",
    }
    uid = _url_id(url)

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            # Step 1 – instant VT-side lookup
            log.info("[VT] GET /urls/%s (instant lookup)", uid)
            lookup = await client.get(f"{VT_BASE_URL}/urls/{uid}", headers=headers)

            if lookup.status_code == 429:
                log.warning("[VT] Rate-limited (429) on lookup")
                return {**_empty, "error": "VirusTotal rate limit reached (429)"}

            if lookup.status_code in (401, 403):
                log.warning("[VT] Access forbidden/unauthorized (HTTP %d) on lookup", lookup.status_code)
                return {**_empty, "error": f"VirusTotal API access restricted (HTTP {lookup.status_code})"}

            if lookup.status_code == 200:
                attrs = lookup.json().get("data", {}).get("attributes", {})
                if attrs.get("last_analysis_stats"):
                    result = _parse_attrs(attrs)
                    log.info(
                        "[VT] Instant result – malicious=%d suspicious=%d vendors=%d risk=%d",
                        result["malicious"], result["suspicious"],
                        result["total_vendors"], result["vt_risk_score"],
                    )
                    return result

            # Step 2 – submit for fresh scan if not cached at VT
            log.info("[VT] POST /urls (submit %s)", url)
            submit = await client.post(
                f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}
            )

            if submit.status_code == 429:
                log.warning("[VT] Rate-limited (429) on submit")
                return {**_empty, "error": "VirusTotal rate limit reached (429)"}

            if submit.status_code not in (200, 201):
                log.error("[VT] Submit failed: HTTP %d  body=%s",
                          submit.status_code, submit.text[:200])
                return {**_empty,
                        "error": f"VirusTotal submit failed: HTTP {submit.status_code}"}

            submit_json  = submit.json()
            analysis_id  = submit_json.get("data", {}).get("id", "")
            poll_url     = (
                f"{VT_BASE_URL}/analyses/{analysis_id}"
                if analysis_id
                else f"{VT_BASE_URL}/urls/{uid}"
            )

            # Step 3 – poll for completion
            for attempt in range(1, POLL_ATTEMPTS + 1):
                await asyncio.sleep(POLL_INTERVAL)
                log.info("[VT] Poll attempt %d/%d – %s", attempt, POLL_ATTEMPTS, poll_url)

                poll = await client.get(poll_url, headers=headers)

                if poll.status_code == 429:
                    log.warning("[VT] Rate-limited (429) during poll attempt %d", attempt)
                    return {**_empty, "error": "VirusTotal rate limit during polling (429)"}

                if poll.status_code != 200:
                    log.warning("[VT] Poll HTTP %d on attempt %d", poll.status_code, attempt)
                    continue

                attrs = poll.json().get("data", {}).get("attributes", {})
                status = attrs.get("status", "")

                if status == "completed" or "last_analysis_stats" in attrs or "stats" in attrs:
                    result = _parse_attrs(attrs)
                    log.info(
                        "[VT] Scan complete – malicious=%d suspicious=%d "
                        "harmless=%d total=%d vendors_flagged=%s risk=%d",
                        result["malicious"], result["suspicious"],
                        result["harmless"],  result["total_vendors"],
                        result["vendors_flagged"][:5],  result["vt_risk_score"],
                    )
                    return result

            log.warning("[VT] Analysis still queued after %d polls", POLL_ATTEMPTS)
            return {**_empty, "error": "VirusTotal analysis still queued – try again shortly"}

    except httpx.TimeoutException:
        log.error("[VT] Request timed out (%.0fs limit)", REQUEST_TIMEOUT)
        return {**_empty, "error": f"VirusTotal request timed out ({REQUEST_TIMEOUT:.0f}s)"}
    except Exception as exc:
        log.exception("[VT] Unexpected error: %s", exc)
        return {**_empty, "error": f"VirusTotal error: {exc}"}
