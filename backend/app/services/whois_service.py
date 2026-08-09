"""
WHOIS Domain Age Service for PhishGuard Engine
100% Free - Uses python-whois library (NO API key required).
Calculates domain registration age and flags newly registered domains (<30 days / <180 days).
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any

try:
    import whois
except ImportError:
    whois = None


def extract_domain(url_or_domain: str) -> str:
    """Extract clean domain name from input URL or text string."""
    if not url_or_domain:
        return ""
    text = url_or_domain.strip().lower()
    if re.search(r"https?://", text):
        parsed = urlparse(text)
        host = parsed.netloc or parsed.path
    else:
        host = text.split("/")[0]
    
    host = host.split(":")[0]  # Remove port
    # Remove leading www.
    if host.startswith("www."):
        host = host[4:]
    return host


def check_domain_age(domain_or_url: str) -> Dict[str, Any]:
    """
    Check domain creation age using python-whois library.
    Returns domain age in days, risk level, risk score (0-100), and rationale.
    """
    domain = extract_domain(domain_or_url)
    fallback: Dict[str, Any] = {
        "domain": domain,
        "age_days": None,
        "creation_date": None,
        "risk": "HIGH",
        "score": 70,
        "reason": "WHOIS information hidden, restricted, or lookup failed",
        "raw_whois_success": False
    }

    if not domain or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or domain in ("localhost", "127.0.0.1"):
        fallback["reason"] = "IP address or local host domain used (no WHOIS creation date)"
        return fallback

    if whois is None:
        print("[WHOIS Service] python-whois library not imported")
        return fallback

    try:
        print(f"[WHOIS Service] Querying WHOIS for {domain}...")
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list) and len(creation_date) > 0:
            creation_date = creation_date[0]

        if not creation_date or not isinstance(creation_date, datetime):
            fallback["reason"] = f"WHOIS data retrieved for {domain} but creation_date unavailable"
            return fallback

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        creation_iso = creation_date.strftime("%Y-%m-%d")

        if age_days < 30:
            return {
                "domain": domain,
                "age_days": age_days,
                "creation_date": creation_iso,
                "risk": "HIGH",
                "score": 85,
                "reason": f"Domain only {age_days} days old (created on {creation_iso}) - newly created for potential scam",
                "raw_whois_success": True
            }
        elif age_days < 180:
            return {
                "domain": domain,
                "age_days": age_days,
                "creation_date": creation_iso,
                "risk": "MEDIUM",
                "score": 50,
                "reason": f"Domain is relatively new ({age_days} days old, created on {creation_iso})",
                "raw_whois_success": True
            }
        else:
            return {
                "domain": domain,
                "age_days": age_days,
                "creation_date": creation_iso,
                "risk": "LOW",
                "score": 10,
                "reason": f"Domain established {age_days} days ago (created on {creation_iso})",
                "raw_whois_success": True
            }

    except Exception as e:
        print(f"[WHOIS Lookup Exception for {domain}]: {e}")
        fallback["reason"] = f"WHOIS hidden or restricted for {domain}"
        return fallback


if __name__ == "__main__":
    res = check_domain_age("http://paypal-secure-login.co")
    print("Test WHOIS output:", res)
