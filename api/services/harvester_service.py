import httpx

async def harvest_subdomains(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if "." not in domain:
        return {"subdomains": [], "count": 0, "risk": 0}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            if r.status_code == 200:
                data = r.json()
                subs = list(set([x['name_value'] for x in data if 'name_value' in x]))[:15]
                count = len(subs)
                risk = 40 if count == 0 else (20 if count < 3 else 0)  # New domain = phishing
                return {"subdomains": subs, "count": count, "risk": risk}
    except Exception:
        pass
    return {"subdomains": [], "count": 0, "risk": 20}
