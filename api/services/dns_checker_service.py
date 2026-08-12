"""
DNS Security Checker Service v3.2

Performs A / MX / SPF / DMARC / NS lookups with reliable public resolvers.
Fixed logic: A record present = NEVER flagged as fake domain.
"""

import asyncio
import re
from typing import Any

import dns.resolver
from dns.exception import DNSException

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

# Reliable public DNS resolvers with fallback
RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def get_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 3.0
    r.timeout = 2.0
    r.nameservers = RESOLVERS
    return r


def extract_domain(url_or_domain: str) -> str:
    """Strip protocol/path and return bare registered domain."""
    url_or_domain = url_or_domain.strip().lower()
    url_or_domain = re.sub(r"^https?://", "", url_or_domain)
    url_or_domain = url_or_domain.split("/")[0].split("?")[0].split("#")[0]

    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(url_or_domain)
        if ext.suffix and ext.domain:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain or url_or_domain
    # Fallback: strip www prefix
    return re.sub(r"^www\.", "", url_or_domain)


async def check_dns_security(url_or_email: str) -> dict[str, Any]:
    """
    Full DNS security check.

    Returns a dict with keys:
        domain, A, A_valid, MX, MX_valid, SPF, SPF_pass,
        DMARC, DMARC_protected, NS, risk, status, details,
        checks (legacy compat keys)
    """
    domain = extract_domain(url_or_email)
    resolver = get_resolver()

    result: dict[str, Any] = {
        "domain": domain,
        "A": None,
        "A_valid": False,
        "MX": None,
        "MX_valid": False,
        "SPF": None,
        "SPF_pass": False,
        "DMARC": None,
        "DMARC_protected": False,
        "NS": [],
        "risk": 0,
        "status": "Unknown",
        "details": [],
        # Legacy compat shape used by scoring.py and ResultCard.jsx
        "checks": {
            "A": False,
            "MX": False,
            "SPF": False,
            "DMARC": False,
        },
    }

    if not domain or "." not in domain:
        result["status"] = "Invalid domain"
        return result

    # ── 1. A Record — does the domain exist? ───────────────────────────────
    try:
        a_answers = resolver.resolve(domain, "A")
        ips = [str(r) for r in a_answers]
        result["A"] = ips
        result["A_valid"] = True
        result["checks"]["A"] = True
        result["details"].append(f"A: {ips[0]}")
    except dns.resolver.NXDOMAIN:
        result["A_valid"] = False
        result["risk"] = 40
        result["status"] = "Domain does not exist - Fake domain"
        result["details"].append("A: NXDOMAIN - domain not found")
        return result  # Stop early — definitely fake
    except dns.resolver.NoAnswer:
        result["A_valid"] = False
        result["details"].append("A: No answer")
    except DNSException as e:
        result["A_valid"] = False
        result["details"].append(f"A: DNS error ({e})")
    except Exception as e:
        result["A_valid"] = False
        result["details"].append(f"A: Error ({e})")

    # ── 2. MX Record ────────────────────────────────────────────────────────
    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in mx_answers]
        result["MX"] = mx_list
        result["MX_valid"] = bool(mx_list)
        result["checks"]["MX"] = result["MX_valid"]
        result["details"].append(f"MX: {mx_list[0]}" if mx_list else "MX: Empty response")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["details"].append("MX: None")
    except Exception as e:
        result["details"].append(f"MX: Error ({e})")

    # ── 3. SPF in TXT records ───────────────────────────────────────────────
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            txt_str = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=spf1" in txt_str.lower():
                result["SPF"] = txt_str
                result["SPF_pass"] = True
                result["checks"]["SPF"] = True
                result["details"].append("SPF: Pass")
                break
        if not result["SPF_pass"]:
            result["details"].append("SPF: None")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["details"].append("SPF: None")
    except Exception as e:
        result["details"].append(f"SPF: Error ({e})")

    # ── 4. DMARC TXT at _dmarc.<domain> ────────────────────────────────────
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_str = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=DMARC1" in txt_str:
                result["DMARC"] = txt_str
                result["DMARC_protected"] = True
                result["checks"]["DMARC"] = True
                result["details"].append("DMARC: Protected")
                break
        if not result["DMARC_protected"]:
            result["details"].append("DMARC: None")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["details"].append("DMARC: None")
    except Exception as e:
        result["details"].append(f"DMARC: Error ({e})")

    # ── 5. NS Record (informational) ────────────────────────────────────────
    try:
        ns_answers = resolver.resolve(domain, "NS")
        result["NS"] = [str(r).rstrip(".") for r in ns_answers]
    except Exception:
        pass

    # ── RISK CALCULATION (NO FALSE POSITIVES) ───────────────────────────────
    a_ok = result["A_valid"]
    mx_ok = result["MX_valid"]
    spf_ok = result["SPF_pass"]
    dmarc_ok = result["DMARC_protected"]

    if not a_ok:
        result["risk"] = 40
        result["status"] = "Domain does not exist - Fake domain"
    elif not mx_ok and not spf_ok:
        result["risk"] = 15
        result["status"] = "No mail server - suspicious (no MX/SPF)"
    elif not mx_ok and spf_ok:
        result["risk"] = 3
        result["status"] = "No MX but SPF present - OK"
    elif a_ok and mx_ok and spf_ok and dmarc_ok:
        result["risk"] = 0
        result["status"] = "Valid - Protected"
    elif not dmarc_ok and spf_ok:
        result["risk"] = 5
        result["status"] = "Missing DMARC - spoofable"
    else:
        result["risk"] = 8
        result["status"] = "Partially configured"

    return result


# Alias for backward compatibility
async def check_dns(domain: str) -> dict[str, Any]:
    return await check_dns_security(domain)
