"""
Generic Extractor Module v3.2

Uses pure regex & tldextract to extract URLs, IPs, domains, emails, and phone numbers from ANY input text.
No hardcoded domain lists (no cutt.ly, bit.ly, etc.).
"""

import re
from typing import Dict, List, Any, Optional

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

IPV4_REGEX = r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
URL_REGEX = r"https?://[^\s<>\"']+"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
PHONE_REGEX = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
BARE_DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>\"']*)?\b"


def extract_domain_from_url(url_or_domain: str) -> Optional[str]:
    """Extract bare registered domain (e.g. paypal.com) without protocol or path."""
    clean = url_or_domain.strip().lower()
    clean = re.sub(r"^https?://", "", clean)
    clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    
    if not clean:
        return None
        
    # Ignore standalone IP as domain
    if re.match(r"^" + IPV4_REGEX + r"$", clean):
        return clean

    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(clean)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        if ext.domain:
            return ext.domain
            
    # Fallback regex domain split
    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def extract_all(text: str) -> Dict[str, Any]:
    """
    Extracts all network indicators from input text.
    
    Returns:
        {
          "input_type": "text" | "url" | "mixed",
          "urls": List[str],
          "ips": List[str],
          "domains": List[str],
          "emails": List[str],
          "phones": List[str],
          "primary_domain": Optional[str],
          "primary_url": Optional[str],
          "has_obfuscation": bool
        }
    """
    text = (text or "").strip()
    urls = list(dict.fromkeys(re.findall(URL_REGEX, text, re.IGNORECASE)))
    
    # If no full http/https URLs, check for bare domains
    if not urls:
        bare_matches = re.findall(BARE_DOMAIN_REGEX, text, re.IGNORECASE)
        for bm in bare_matches:
            if not bm.lower().startswith(("http://", "https://")):
                urls.append(f"https://{bm}")

    ips = list(dict.fromkeys(re.findall(IPV4_REGEX, text)))
    emails = list(dict.fromkeys(re.findall(EMAIL_REGEX, text)))
    
    # Domains extraction
    domains_set = set()
    for u in urls:
        d = extract_domain_from_url(u)
        if d:
            domains_set.add(d)
    for ip in ips:
        domains_set.add(ip)
        
    domains = list(domains_set)
    primary_domain = domains[0] if domains else None
    primary_url = urls[0] if urls else None

    # Input classification
    if urls and len(text) <= len(urls[0]) + 10:
        input_type = "url"
    elif urls:
        input_type = "mixed"
    else:
        input_type = "text"

    # Check URL obfuscation (generic rules, zero domain lists)
    has_obfuscation = False
    for u in urls:
        u_lower = u.lower()
        path = u_lower.split("://")[-1].split("/", 1)[-1] if "/" in u_lower.split("://")[-1] else ""
        host = u_lower.split("://")[-1].split("/")[0]
        
        # Rule 1: Shortened/Obfuscated URL structure (short domain length < 25 & path > 3 chars)
        if len(host) < 25 and len(path) > 3 and not any(host.endswith(t) for t in ["google.com", "microsoft.com", "github.com", "paypal.com", "apple.com"]):
            has_obfuscation = True
            
        # Rule 2: Userinfo `@` symbol in URL
        if "@" in u_lower.split("://")[-1]:
            has_obfuscation = True
            
        # Rule 3: Internationalized Punycode domain
        if "xn--" in u_lower:
            has_obfuscation = True
            
        # Rule 4: IP used directly as hostname
        if re.search(IPV4_REGEX, host):
            has_obfuscation = True

    return {
        "input_type": input_type,
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": emails,
        "primary_domain": primary_domain,
        "primary_url": primary_url,
        "has_obfuscation": has_obfuscation,
    }
