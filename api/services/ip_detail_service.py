import dns.resolver
import httpx
import re
import ipaddress

async def get_ip_details(target: str):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ip = None

    # If target is IP
    try:
        ipaddress.ip_address(domain)
        ip = domain
    except Exception:
        # Resolve domain to IP
        try:
            ip = dns.resolver.resolve(domain, 'A', lifetime=3)[0].to_text()
        except Exception:
            return {"ip": None, "risk": 20, "error": "No IP found"}

    details = {
        "ip": ip,
        "risk": 0,
        "geo": {},
        "asn": {},
        "is_proxy": False,
        "is_hosting": False,
        "blacklist": {}
    }

    # Free IP geolocation - ip-api.com no key, 45 req/min, Vercel safe
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query")
            if r.status_code == 200:
                data = r.json()
                details["geo"] = {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city")
                }
                details["asn"] = {
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as")
                }
                details["is_proxy"] = data.get("proxy", False)
                details["is_hosting"] = data.get("hosting", False)

                if details["is_proxy"]:
                    details["risk"] += 25
                if details["is_hosting"]:
                    details["risk"] += 10  # Hosting IP often used for phishing

                # Bulletproof hosting check
                suspicious_isps = ["OVH", "Hostinger", "Namecheap", "DigitalOcean", "Linode", "Vultr"]
                isp_org = (data.get("isp", "") or "") + (data.get("org", "") or "")
                if any(x.lower() in isp_org.lower() for x in suspicious_isps):
                    details["risk"] += 10
    except Exception as e:
        details["geo"] = {"error": str(e)}

    # Check if IP is private/bogon
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            details["risk"] += 30
    except Exception:
        pass

    return details
