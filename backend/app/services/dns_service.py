"""
DNS Enricher Service v3.2 - Triple Fallback Architecture

Lookup order for A record:
1. dnspython (Google 8.8.8.8 / Cloudflare 1.1.1.1)
2. Python socket.gethostbyname()
3. Google DNS over HTTPS (https://dns.google/resolve)

Never returns N/A or crashes. If no domain is provided, returns is_applicable=False.
"""

import socket
import asyncio
import httpx
from typing import Dict, Any, Optional

import dns.resolver
from dns.exception import DNSException


def get_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 2.5
    r.timeout = 2.0
    r.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    return r


async def resolve_doh_google(domain: str, record_type: str = "A") -> list[str]:
    """Fallback 3: Resolve DNS via Google DNS-over-HTTPS API."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": record_type}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                return [ans["data"] for ans in answers if "data" in ans]
    except Exception:
        pass
    return []


async def enrich_dns(domain: Optional[str]) -> Dict[str, Any]:
    """
    Enriches domain with DNS security records.
    Never crashes, never returns hardcoded N/A.
    """
    if not domain or "." not in domain:
        return {
            "is_applicable": False,
            "domain": domain or "",
            "A_valid": None,
            "MX_valid": None,
            "SPF_pass": None,
            "DMARC_protected": None,
            "A": [],
            "MX": [],
            "SPF": None,
            "DMARC": None,
            "risk": 0,
            "status": "No domain to check",
            "details": ["Text analysis only - No domain specified"],
            "checks": {"A": None, "MX": None, "SPF": None, "DMARC": None}
        }

    clean_domain = domain.strip().lower()
    resolver = get_resolver()

    a_ips = []
    a_valid = False
    
    # ── 1. A Record (Triple Fallback) ──
    # Method 1: dnspython
    try:
        a_ans = resolver.resolve(clean_domain, "A")
        a_ips = [str(r) for r in a_ans]
        a_valid = len(a_ips) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        a_valid = False
    except Exception:
        pass

    # Method 2: socket fallback (if dnspython failed to confirm)
    if not a_valid:
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, clean_domain)
            if ip:
                a_ips = [ip]
                a_valid = True
        except Exception:
            pass

    # Method 3: Google DoH fallback
    if not a_valid:
        doh_ips = await resolve_doh_google(clean_domain, "A")
        if doh_ips:
            a_ips = doh_ips
            a_valid = True

    # If domain cannot be resolved by any method -> Domain does not exist (Fake)
    if not a_valid:
        return {
            "is_applicable": True,
            "domain": clean_domain,
            "A_valid": False,
            "MX_valid": False,
            "SPF_pass": False,
            "DMARC_protected": False,
            "A": [],
            "MX": [],
            "SPF": None,
            "DMARC": None,
            "risk": 40,
            "status": "Domain does not exist - Unresolvable",
            "details": ["A: NXDOMAIN / Unresolvable via 3 DNS methods"],
            "checks": {"A": False, "MX": False, "SPF": False, "DMARC": False}
        }

    # ── 2. MX Record ──
    mx_list = []
    mx_valid = False
    try:
        mx_ans = resolver.resolve(clean_domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in mx_ans]
        mx_valid = len(mx_list) > 0
    except Exception:
        doh_mx = await resolve_doh_google(clean_domain, "MX")
        if doh_mx:
            mx_list = doh_mx
            mx_valid = True

    # ── 3. SPF Record ──
    spf_pass = False
    spf_str = None
    try:
        txt_ans = resolver.resolve(clean_domain, "TXT")
        for rdata in txt_ans:
            txt_val = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=spf1" in txt_val.lower():
                spf_pass = True
                spf_str = txt_val
                break
    except Exception:
        pass

    if not spf_pass:
        doh_txt = await resolve_doh_google(clean_domain, "TXT")
        for t in doh_txt:
            if "v=spf1" in t.lower():
                spf_pass = True
                spf_str = t
                break

    # ── 4. DMARC Record ──
    dmarc_protected = False
    dmarc_str = None
    try:
        dmarc_ans = resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
        for rdata in dmarc_ans:
            txt_val = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=DMARC1" in txt_val:
                dmarc_protected = True
                dmarc_str = txt_val
                break
    except Exception:
        pass

    # ── Risk Scoring & Status ──
    if not mx_valid and not spf_pass:
        risk = 15
        status = "No mail server - suspicious (no MX/SPF)"
    elif not mx_valid and spf_pass:
        risk = 3
        status = "No MX but SPF present - OK"
    elif a_valid and mx_valid and spf_pass and dmarc_protected:
        risk = 0
        status = "Valid - Protected"
    elif not dmarc_protected and spf_pass:
        risk = 5
        status = "Missing DMARC - spoofable"
    else:
        risk = 8
        status = "Partially configured"

    return {
        "is_applicable": True,
        "domain": clean_domain,
        "A_valid": True,
        "MX_valid": mx_valid,
        "SPF_pass": spf_pass,
        "DMARC_protected": dmarc_protected,
        "A": a_ips,
        "MX": mx_list,
        "SPF": spf_str,
        "DMARC": dmarc_str,
        "risk": risk,
        "status": status,
        "details": [
            f"A: {a_ips[0]}" if a_ips else "A: Valid",
            f"MX: {mx_list[0]}" if mx_list else "MX: None",
            "SPF: Pass" if spf_pass else "SPF: None",
            "DMARC: Protected" if dmarc_protected else "DMARC: None"
        ],
        "checks": {
            "A": True,
            "MX": mx_valid,
            "SPF": spf_pass,
            "DMARC": dmarc_protected
        }
    }
