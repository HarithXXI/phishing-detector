"""
IP Enricher Service v3.2

Resolves IP via socket and fetches ISP/geolocation data from ip-api.com (free, no API key).
Never returns N/A or crashes. If no input or resolution fails, returns clean fallback state.
"""

import socket
import asyncio
import re
import httpx
from typing import Dict, Any, Optional

IPV4_REGEX = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"


async def enrich_ip(target: Optional[str]) -> Dict[str, Any]:
    """
    Resolves domain/IP and retrieves network & hosting details.
    """
    if not target or target.strip() in ["", "none", "null"]:
        return {
            "is_applicable": False,
            "ip": "",
            "location": "No IP to check",
            "city": "",
            "country": "",
            "isp": "Text analysis only",
            "org": "",
            "is_hosting": False,
            "is_proxy": False,
            "risk": 0,
            "status": "No IP to check",
            "geo": {"city": "", "country": ""},
            "asn": {"isp": "Text analysis only", "org": ""}
        }

    clean_target = target.strip().lower()
    clean_target = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0]

    # Step 1: Resolve IP via socket if domain provided
    resolved_ip = clean_target
    if not re.match(IPV4_REGEX, clean_target):
        try:
            resolved_ip = await asyncio.to_thread(socket.gethostbyname, clean_target)
        except Exception:
            return {
                "is_applicable": True,
                "ip": "Unresolvable",
                "location": "Unresolved Domain",
                "city": "",
                "country": "",
                "isp": "DNS Resolution Failed",
                "org": "",
                "is_hosting": False,
                "is_proxy": False,
                "risk": 0,
                "status": "Unresolvable Host",
                "geo": {"city": "Unresolved", "country": ""},
                "asn": {"isp": "DNS Failed", "org": ""}
            }

    # Step 2: Fetch IP intelligence from ip-api.com (3s timeout)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{resolved_ip}?fields=status,country,city,isp,org,hosting,proxy")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    city = data.get("city", "")
                    country = data.get("country", "")
                    isp = data.get("isp", "Cloud Provider")
                    org = data.get("org", "")
                    is_hosting = bool(data.get("hosting", False))
                    is_proxy = bool(data.get("proxy", False))

                    location = f"{city}, {country}".strip(", ") or country or "Global IP"

                    risk = 0
                    if is_proxy:
                        risk = 25
                        status = "Proxy / VPN Node"
                    elif is_hosting:
                        risk = 5
                        status = "Datacenter / Hosting IP"
                    else:
                        risk = 0
                        status = "Residential / Standard IP"

                    return {
                        "is_applicable": True,
                        "ip": resolved_ip,
                        "location": location,
                        "city": city,
                        "country": country,
                        "isp": isp,
                        "org": org,
                        "is_hosting": is_hosting,
                        "is_proxy": is_proxy,
                        "risk": risk,
                        "status": status,
                        "geo": {"city": city, "country": country},
                        "asn": {"isp": isp, "org": org}
                    }
    except Exception:
        pass

    # Fallback if API lookup fails/times out
    return {
        "is_applicable": True,
        "ip": resolved_ip,
        "location": "Global IP Node",
        "city": "",
        "country": "",
        "isp": "Resolved Network Host",
        "org": "",
        "is_hosting": False,
        "is_proxy": False,
        "risk": 0,
        "status": "Resolved IP",
        "geo": {"city": "Global", "country": "Node"},
        "asn": {"isp": "Resolved Host", "org": ""}
    }
