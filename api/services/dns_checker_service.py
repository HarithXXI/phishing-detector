import dns.resolver
import re

async def check_dns_full(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SPF": None,
        "DMARC": None,
        "DKIM": False,
        "risk": 0,
        "checks": {}
    }
    try:
        result["A"] = [r.to_text() for r in dns.resolver.resolve(domain, 'A', lifetime=3)]
        result["checks"]["A"] = True
    except Exception:
        result["checks"]["A"] = False
        result["risk"] += 25

    try:
        result["AAAA"] = [r.to_text() for r in dns.resolver.resolve(domain, 'AAAA', lifetime=3)]
    except Exception:
        pass

    try:
        result["MX"] = [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX', lifetime=3)]
        result["checks"]["MX"] = len(result["MX"]) > 0
        if not result["MX"]:
            result["risk"] += 30
    except Exception:
        result["checks"]["MX"] = False
        result["risk"] += 30

    try:
        result["NS"] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS', lifetime=3)]
        result["checks"]["NS"] = True
    except Exception:
        result["checks"]["NS"] = False
        result["risk"] += 15

    try:
        txts = [r.to_text() for r in dns.resolver.resolve(domain, 'TXT', lifetime=3)]
        result["TXT"] = txts
        result["SPF"] = next((t for t in txts if "v=spf1" in t), None)
        result["checks"]["SPF"] = result["SPF"] is not None
        if not result["SPF"]:
            result["risk"] += 15

        # Check DMARC
        try:
            dmarc = [r.to_text() for r in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=3)]
            result["DMARC"] = dmarc[0] if dmarc else None
            result["checks"]["DMARC"] = result["DMARC"] is not None
            if not result["DMARC"]:
                result["risk"] += 10
        except Exception:
            result["checks"]["DMARC"] = False
            result["risk"] += 10
    except Exception:
        result["checks"]["SPF"] = False
        result["risk"] += 25

    return result
