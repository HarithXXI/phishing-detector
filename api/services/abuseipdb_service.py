"""
AbuseIPDB Threat Intelligence Service
Checks IP addresses against the AbuseIPDB v2 API database.
"""

import asyncio
import ipaddress
import logging
import os
import re
import socket
import httpx

log = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REQUEST_TIMEOUT = 8.0


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP string is a private or reserved IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False


def _extract_ip_or_domain(text: str) -> tuple[str | None, str | None]:
    """Extract raw IP address or domain from text."""
    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    if ip_match:
        return ip_match.group(0), None

    url_match = re.search(r"https?://([^\s/:]+)", text, re.IGNORECASE)
    if url_match:
        return None, url_match.group(1).lower()

    domain_match = re.search(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|gov|edu|io|info|work|site|online|tech|app|xyz|top|live|me|co|in|ly)\b",
        text,
        re.IGNORECASE,
    )
    if domain_match:
        return None, domain_match.group(0).lower()

    return None, None


async def check_abuseipdb(input_text: str) -> dict:
    """
    Checks an IP or resolves a domain to an IP and queries AbuseIPDB.
    """
    fallback = {
        "ipAddress": None,
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "country": None,
        "isp": None,
        "lastReportedAt": None,
        "isWhitelisted": False,
        "risk_score": 5,
        "error": None,
    }

    if not ABUSEIPDB_API_KEY:
        fallback["error"] = "AbuseIPDB API key not configured"
        return fallback

    ip_str, domain_str = _extract_ip_or_domain(input_text)

    if not ip_str and domain_str:
        try:
            loop = asyncio.get_event_loop()
            ip_str = await loop.run_in_executor(None, socket.gethostbyname, domain_str)
        except Exception as exc:
            fallback["error"] = f"DNS resolution failed for '{domain_str}': {exc}"
            return fallback

    if not ip_str:
        fallback["error"] = f"No valid IP found or resolved from: {input_text[:50]}"
        return fallback

    if _is_private_ip(ip_str):
        fallback["ipAddress"] = ip_str
        fallback["error"] = f"IP {ip_str} is a private/local IP address"
        return fallback

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
        "User-Agent": "PhishGuard/1.0",
    }
    params = {"ipAddress": ip_str, "maxAgeInDays": "90", "verbose": ""}

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(f"{ABUSEIPDB_BASE_URL}/check", headers=headers, params=params)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)

                if score >= 50:
                    risk_score = 85
                elif score >= 20:
                    risk_score = 50
                elif score > 0:
                    risk_score = 25
                else:
                    risk_score = 5

                return {
                    "ipAddress": data.get("ipAddress", ip_str),
                    "abuseConfidenceScore": score,
                    "totalReports": data.get("totalReports", 0),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "isWhitelisted": data.get("isWhitelisted", False),
                    "risk_score": risk_score,
                    "error": None,
                }
    except Exception as exc:
        fallback["error"] = f"AbuseIPDB request error: {exc}"

    return fallback
