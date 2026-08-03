"""
AbuseIPDB Threat Intelligence Service

Checks IP addresses (or resolves domains/URLs to IP addresses)
against the AbuseIPDB v2 API database for known abuse reports.

API docs: https://docs.abuseipdb.com/
"""

import asyncio
import ipaddress
import logging
import re
import socket
import httpx

from app.config import ABUSEIPDB_API_KEY

log = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REQUEST_TIMEOUT = 8.0


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP string is a private, loopback, or reserved IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False


async def _extract_ip_or_resolve(target: str) -> tuple[str | None, bool]:
    """
    Extract public IPv4 address from target via regex.
    If direct IP is private/loopback, note it and try domain resolution.
    Runs DNS resolution in a thread pool with strict 3.0s timeout to never block the main loop.
    Returns (ip_str, is_private_flag).
    """
    if not target:
        return None, False

    # 1. Check for direct valid IPv4 (0-255 octets)
    ip_matches = re.findall(
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        target,
    )
    for ip in ip_matches:
        if not _is_private_ip(ip):
            return ip, False

    # 2. Extract valid domain ONLY (e.g., bit.ly, paypal.com, google.com)
    # Target URL or bare domain matching
    domain_match = re.search(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|gov|edu|io|info|work|site|online|tech|app|xyz|top|live|me|co|in|ly)\b",
        target,
        re.IGNORECASE,
    )
    if domain_match:
        domain = domain_match.group(0).lower()
        try:
            # Non-blocking DNS resolution in threadpool with 3.0s max timeout
            resolved_ip = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyname, domain),
                timeout=3.0
            )
            if not _is_private_ip(resolved_ip):
                log.info("[AbuseIPDB] Resolved domain '%s' to public IP %s", domain, resolved_ip)
                return resolved_ip, False
            else:
                log.info("[AbuseIPDB] Domain '%s' resolved to private IP %s", domain, resolved_ip)
                return resolved_ip, True
        except Exception as err:
            log.warning("[AbuseIPDB] Non-blocking DNS lookup skipped for domain '%s': %s", domain, err)

    # If only private IP was found
    if ip_matches:
        return ip_matches[0], True

    return None, False


def calculate_abuse_risk(score: int, total_reports: int) -> int:
    """
    Risk scoring logic:
      >= 75       -> 90
      50-74       -> 65
      25-49       -> 40
      reports > 0 -> 25
      else        -> 5
    """
    if score >= 75:
        return 90
    elif score >= 50:
        return 65
    elif score >= 25:
        return 40
    elif total_reports > 0:
        return 25
    return 5


async def check_abuseipdb(target: str) -> dict:
    """
    Check an IP address or domain target against AbuseIPDB.

    Args:
        target: IP address, URL, or domain name.

    Returns:
        dict containing abuseConfidenceScore, totalReports, country, isp,
        lastReportedAt, isWhitelisted, risk_score, and error.
    """
    result = {
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
        log.warning("[AbuseIPDB] API key not configured")
        # pyrefly: ignore [bad-assignment]
        result["error"] = "AbuseIPDB API key not configured"
        return result

    ip, is_private = await _extract_ip_or_resolve(target)
    if not ip:
        # pyrefly: ignore [bad-assignment]
        result["error"] = f"No valid IP found or resolved from: {target}"
        return result

    # pyrefly: ignore [bad-assignment]
    result["ipAddress"] = ip

    # Handle private / LAN IP gracefully without triggering HTTP 422 API error
    if is_private:
        log.info("[AbuseIPDB] Target '%s' is a private/LAN IP (%s) – skipping public API query", target, ip)
        # pyrefly: ignore [no-matching-overload]
        result.update({
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "country": "LAN / Private Network",
            "isp": "Private IP Address",
            "isWhitelisted": True,
            "risk_score": 5,
            "error": "Private / Internal IP address (Not queried on public AbuseIPDB)",
        })
        return result

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
        "User-Agent": "PhishGuard/1.0",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "true",
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            log.info("[AbuseIPDB] Checking IP %s on AbuseIPDB...", ip)
            resp = await client.get(
                f"{ABUSEIPDB_BASE_URL}/check",
                headers=headers,
                params=params,
            )

            if resp.status_code == 429:
                log.warning("[AbuseIPDB] Rate limit reached (429)")
                # pyrefly: ignore [bad-assignment]
                result["error"] = "AbuseIPDB rate limit reached (429)"
                return result

            if resp.status_code != 200:
                log.error("[AbuseIPDB] Request failed: HTTP %d %s", resp.status_code, resp.text[:200])
                # pyrefly: ignore [bad-assignment]
                result["error"] = f"AbuseIPDB request failed: HTTP {resp.status_code}"
                return result

            data = resp.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode") or data.get("countryName")
            isp = data.get("isp")
            last_reported_at = data.get("lastReportedAt")
            is_whitelisted = data.get("isWhitelisted", False)

            risk_score = calculate_abuse_risk(score, total_reports)

            result.update({
                "abuseConfidenceScore": score,
                "totalReports": total_reports,
                "country": country,
                "isp": isp,
                "lastReportedAt": last_reported_at,
                "isWhitelisted": is_whitelisted,
                "risk_score": risk_score,
            })

            log.info(
                "[AbuseIPDB] IP %s → score=%d reports=%d country=%s isp=%s whitelisted=%s risk=%d",
                ip, score, total_reports, country, isp, is_whitelisted, risk_score
            )

    except httpx.TimeoutException:
        log.error("[AbuseIPDB] Request timed out (%.0fs limit)", REQUEST_TIMEOUT)
        # pyrefly: ignore [bad-assignment]
        result["error"] = f"AbuseIPDB request timed out ({REQUEST_TIMEOUT:.0f}s)"
    except Exception as exc:
        log.exception("[AbuseIPDB] Unexpected error checking %s: %s", ip, exc)
        # pyrefly: ignore [bad-assignment]
        result["error"] = f"AbuseIPDB error: {exc}"

    return result
