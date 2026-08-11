import dns.resolver

async def check_dns_records(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    records = {"A": [], "MX": [], "TXT": [], "NS": []}
    risk = 0
    try:
        records["A"] = [r.to_text() for r in dns.resolver.resolve(domain, 'A', lifetime=3)]
    except Exception:
        pass
    try:
        records["MX"] = [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX', lifetime=3)]
    except Exception:
        pass
    try:
        records["TXT"] = [r.to_text() for r in dns.resolver.resolve(domain, 'TXT', lifetime=3)]
    except Exception:
        pass
    try:
        records["NS"] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS', lifetime=3)]
    except Exception:
        pass
    if not records["MX"]:
        risk += 30  # No mail server = fake domain
    if not records["TXT"]:
        risk += 15  # No SPF/DMARC
    if not records["A"]:
        risk += 25  # No A record
    return {
        "records": records,
        "risk": risk,
        "is_suspicious": risk > 20,
        "has_mx": len(records["MX"]) > 0
    }
