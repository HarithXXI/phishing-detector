"""
URL Heuristic Phishing Detection Engine
Analyzes URL structure for phishing signals.
"""

import re
from urllib.parse import urlparse

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
    flags = []
    
    try:
        parsed = urlparse(url)
    except Exception:
        return ["Malformed URL structure"]

    domain = parsed.netloc or parsed.path.split("/")[0]
    domain_lower = domain.lower()

    if parsed.scheme == "http":
        if any(k in url.lower() for k in ["login", "verify", "secure", "account", "bank", "update"]):
            flags.append("HTTP (no TLS) with sensitive keyword 'login' in URL")

    if "@" in domain:
        flags.append("Suspicious '@' symbol in URL (credential embedding trick)")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        flags.append(f"IP address used instead of domain name ({domain})")

    parts = domain_lower.split(".")
    if len(parts) > 3:
        flags.append(f"Excessive subdomains detected ({len(parts)} levels)")

    for brand in SPOOFED_BRANDS:
        if brand in domain_lower:
            legit = f"{brand}.com"
            if not domain_lower.endswith(legit) and not domain_lower == brand:
                flags.append(f"Brand spoofing detected: '{brand}' in unofficial domain '{domain}'")

    if domain_lower.count("-") >= 2:
        flags.append(f"Excessive hyphens in domain: {domain}")

    suspicious_tlds = [".xyz", ".top", ".work", ".click", ".link", ".live", ".info", ".online", ".site", ".buzz", ".monster"]
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            flags.append(f"High-risk TLD detected: '{tld}'")

    for brand in SPOOFED_BRANDS:
        typos = [
            f"paypa1", f"paypaI", f"app1e", f"g00gle", f"micros0ft",
            f"amaz0n", f"netf1ix", f"faceb00k", f"insta-gram", f"wha-tsapp"
        ]
        for typo in typos:
            if typo in domain_lower:
                flags.append(f"Typosquatting / Brand spoofing detected for '{brand}' in {domain}")

    return flags


def check_url_heuristics(text: str) -> tuple[list[str], list[str]]:
    """
    Extract URLs from text and run heuristic rules on each.
    Returns (all_risk_flags, list_of_urls_found).
    """
    urls = _extract_urls(text)
    if not urls:
        return [], []

    all_flags = []
    for u in urls:
        url_flags = _check_single_url(u)
        all_flags.extend(url_flags)

    seen = set()
    deduped_flags = []
    for f in all_flags:
        if f not in seen:
            seen.add(f)
            deduped_flags.append(f)

    return deduped_flags, urls
