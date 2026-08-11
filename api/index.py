import sys
import os
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.rule_engine import check_rules
from services.url_heuristic import check_url_heuristics
from services.whois_service import check_domain_age
from services.virustotal_service import check_virustotal
from services.abuseipdb_service import check_abuseipdb
from services.gemini_service import analyze_with_gemini
from services.dns_checker_service import check_dns_full
from services.ip_detail_service import get_ip_details
from services.phone_osint_service import check_phone_osint
from services.harvester_service import harvest_subdomains
from services.wfuzz_service import fuzz_phishing_paths
from utils.scoring import calculate_composite_score

app = FastAPI(title="PhishGuard v3.1 OSINT Engine")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class AnalyzeRequest(BaseModel):
    text: str


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest):
    text = payload.text.strip()
    if not text:
        return {"error": "Empty"}

    rule_risks = check_rules(text)
    url_risks, urls = check_url_heuristics(text)
    target = urls[0] if urls else text
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    whois_res = check_domain_age(target)

    async def safe_vt() -> dict:
        try:
            res = await asyncio.wait_for(check_virustotal(target), timeout=3)
            return res if isinstance(res, dict) else {"malicious": 0}
        except Exception:
            return {"malicious": 0}

    async def safe_abuse() -> dict:
        try:
            res = await asyncio.wait_for(check_abuseipdb(text), timeout=3)
            return res if isinstance(res, dict) else {"risk_score": 0}
        except Exception:
            return {"risk_score": 0}

    async def safe_ai() -> dict:
        try:
            res = await asyncio.wait_for(analyze_with_gemini(text), timeout=4)
            return res if isinstance(res, dict) else {"is_phishing": False, "risk_level": "LOW"}
        except Exception:
            return {"is_phishing": False, "risk_level": "LOW"}

    async def safe_harvest() -> dict:
        if "." in domain:
            try:
                res = await harvest_subdomains(domain)
                return res if isinstance(res, dict) else {"risk": 0}
            except Exception:
                return {"risk": 0}
        return {"risk": 0}

    async def safe_wfuzz() -> dict:
        if urls:
            try:
                res = await fuzz_phishing_paths(urls[0])
                return res if isinstance(res, dict) else {"risk": 0}
            except Exception:
                return {"risk": 0}
        return {"risk": 0}

    vt_res, abuse_res, ai_res, dns_res, ip_res, harvest_res, phone_res, wfuzz_res = await asyncio.gather(
        safe_vt(),
        safe_abuse(),
        safe_ai(),
        check_dns_full(domain),
        get_ip_details(target),
        safe_harvest(),
        check_phone_osint(text),
        safe_wfuzz()
    )

    vt_dict: dict = vt_res if isinstance(vt_res, dict) else {"malicious": 0}
    abuse_dict: dict = abuse_res if isinstance(abuse_res, dict) else {"risk_score": 0}
    ai_dict: dict = ai_res if isinstance(ai_res, dict) else {"is_phishing": False, "risk_level": "LOW"}
    whois_dict: dict = whois_res if isinstance(whois_res, dict) else {}

    dns_risk = dns_res.get("risk", 0) if isinstance(dns_res, dict) else 0
    ip_risk = ip_res.get("risk", 0) if isinstance(ip_res, dict) else 0
    harvest_risk = harvest_res.get("risk", 0) if isinstance(harvest_res, dict) else 0
    wfuzz_risk = wfuzz_res.get("risk", 0) if isinstance(wfuzz_res, dict) else 0

    osint_score = dns_risk + ip_risk + harvest_risk + wfuzz_risk
    base_scoring = calculate_composite_score(rule_risks, url_risks, vt_dict, abuse_dict, ai_dict, whois_dict, {"ml_score": 0})
    final_score = min(100, base_scoring["score"] + osint_score)

    return {
        "score": final_score,
        "risk_level": "CRITICAL" if final_score >= 75 else "HIGH" if final_score >= 50 else "MEDIUM" if final_score >= 25 else "LOW",
        "risks": rule_risks + url_risks,
        "whois": whois_res,
        "virustotal": vt_res,
        "abuseipdb": abuse_res,
        "ai_result": ai_res,
        "dns": dns_res,
        "ip_details": ip_res,
        "osint": {
            "phone": phone_res,
            "harvester": harvest_res,
            "wfuzz": wfuzz_res,
            "osint_score": osint_score
        },
        "breakdown": base_scoring["breakdown"],
        "urls_found": urls
    }


@app.post("/api/chat")
async def chat(body: dict):
    from services.gemini_service import chat_with_gemini
    return await chat_with_gemini(body.get("message", ""))


@app.get("/api/preview")
async def preview(url: str):
    import httpx
    async with httpx.AsyncClient() as c:
        r = await c.get(f"https://api.microlink.io?url={url}", timeout=5)
        return r.json()


@app.post("/api/phone-intel")
async def phone_intel(payload: dict):
    from services.phone_osint_service import check_phone_osint_detailed
    phone = payload.get("phone", "")
    return await check_phone_osint_detailed(phone)


@app.post("/api/phone-bulk")
async def phone_bulk(payload: dict):
    from services.phone_osint_service import check_phone_osint
    text = payload.get("text", "")
    results = await check_phone_osint(text)
    return {"phones": results, "count": len(results)}


@app.get("/api")
def health():
    return {"status": "v3.1 OSINT Vercel-only"}
