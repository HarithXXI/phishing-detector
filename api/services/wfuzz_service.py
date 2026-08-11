import httpx
import asyncio

PATHS = ["/login", "/verify", "/admin", "/secure", "/webscr", "/signin"]

async def fuzz_phishing_paths(base_url: str):
    if not base_url:
        return {"exposed_paths": [], "count": 0, "risk": 0, "is_phishing_kit": False}
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")
    found = []
    try:
        async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
            async def check(p):
                try:
                    r = await client.get(base_url + p)
                    if r.status_code in [200, 301, 302, 403]:
                        return p
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*[check(p) for p in PATHS])
            found = [x for x in results if x]
    except Exception:
        pass
    return {
        "exposed_paths": found,
        "count": len(found),
        "risk": len(found) * 15,
        "is_phishing_kit": len(found) >= 2
    }
