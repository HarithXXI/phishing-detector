"""
URL Heuristic Phishing Detection Engine

Analyzes URL structure for phishing signals.
Purely deterministic — no API calls, no ML.
"""

import re
from urllib.parse import urlparse


# Brands commonly spoofed in phishing
SPOOFED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "bank",
    "chase", "wellsfargo", "citi", "dropbox", "linkedin",
]


def _extract_urls(text: str) -> list[str]:
    """Pull all http/https URLs and bare domains from text."""
    full_urls = re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
    
    bare_matches = re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|gov|edu|io|info|work|site|online|tech|app|xyz|top|live|me|co|in|ly)(?:/[^\s<>\"']*)?\b",
        text,
        re.IGNORECASE,
    )
    
    combined = list(full_urls)
    for b in bare_matches:
        formatted = f"https://{b}" if not b.startswith("http") else b
        if formatted not in combined and b not in combined:
            combined.append(formatted)

    return combined


def _check_single_url(url: str) -> list[str]:
    """Run all heuristic checks on a single URL."""
    risks = []

    try:
        parsed = urlparse(url)
    except Exception:
        risks.append(f"Malformed URL: {url}")
        return risks

    hostname = parsed.hostname or ""
    full_url = url

    # 1. IP address as hostname
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        risks.append(f"IP address used as hostname: {hostname}")

    # 2. @ symbol in URL (credential confusion attack)
    if "@" in full_url:
        risks.append(f"URL contains '@' symbol (credential confusion): {url}")

    # 3. Excessive URL length
    if len(full_url) > 75:
        risks.append(f"Suspiciously long URL ({len(full_url)} chars)")

    # 4. 3+ subdomains (deep nesting)
    parts = hostname.split(".")
    if len(parts) >= 4:
        risks.append(f"Deep subdomain nesting ({len(parts)} levels): {hostname}")

    # 5. Brand Spoofing & Typosquatting
    # Brands list including postal/banking/tech services
    extended_brands = SPOOFED_BRANDS + ["delhivery", "fedex", "dhl", "usps"]
    
    # 5a. Check brand presence in IP URL or non-official domain
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    for brand in extended_brands:
        official_domain = f"{brand}.com"
        # If brand is in URL path/query/hostname but hostname is an IP or not official domain
        if brand in full_url.lower() and not hostname.lower().endswith(official_domain):
            if is_ip:
                risks.append(f"Brand spoofing detected: '{brand}' targeted via IP address URL ({hostname})")
            else:
                risks.append(f"Brand spoofing detected: '{brand}' in unofficial domain '{hostname}'")
            break

    # 5b. Typosquatting / Leetspeak detection (e.g. paypa1.com, goog1e, micros0ft)
    typosquat_patterns = [
        (r"paypa[1l|i]", "paypal"),
        (r"goog[1l|i]e", "google"),
        (r"micros[0o]ft", "microsoft"),
        (r"amaz[0o]n", "amazon"),
        (r"chase-[a-z0-9-]+", "chase"),
    ]
    for pattern, target_brand in typosquat_patterns:
        if re.search(pattern, hostname, re.IGNORECASE) and not hostname.lower().endswith(f"{target_brand}.com"):
            risks.append(f"Typosquatting / Brand spoofing detected for '{target_brand}' in {hostname}")
            break

    # 6. Punycode / IDN homograph attack
    if "xn--" in hostname:
        risks.append(f"Punycode (IDN homograph) domain detected: {hostname}")

    # 7. HTTP (no TLS) with sensitive keyword in path or hostname
    if parsed.scheme == "http":
        path_and_query = (parsed.path + "?" + (parsed.query or "")).lower()
        login_keywords = ["login", "signin", "verify", "account", "secure", "update", "confirm", "track", "pay"]
        for kw in login_keywords:
            if kw in path_and_query or kw in hostname:
                risks.append(f"HTTP (no TLS) with sensitive keyword '{kw}' in URL")
                break

    # 8. Excessive hyphens in domain
    if hostname.count("-") >= 2:
        risks.append(f"Excessive hyphens in domain: {hostname}")

    # 9. Suspicious TLD
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".work", ".site", ".online"]
    for tld in suspicious_tlds:
        if hostname.endswith(tld):
            risks.append(f"Suspicious TLD detected: {tld}")
            break

    # 10. URL Shortener detection
    shorteners = ["cutt.ly", "cutt.us", "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", "rb.gy", "tiny.cc", "shorturl.at", "clck.ru", "rotf.lol", "soo.gd"]
    for s in shorteners:
        if s in hostname.lower():
            risks.append(f"URL Shortener detected ({s}) used to obscure destination")
            break

    return risks


def check_url_heuristics(text: str) -> tuple[list[str], list[str]]:
    """
    Extract URLs from text and run heuristic checks on each.

    Args:
        text: Raw input text that may contain URLs.

    Returns:
        Tuple of (risks list, extracted_urls list).
    """
    urls = _extract_urls(text)
    all_risks = []

    for url in urls:
        all_risks.extend(_check_single_url(url))

    return all_risks, urls
