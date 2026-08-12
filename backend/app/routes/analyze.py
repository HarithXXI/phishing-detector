"""
Analysis Router v3.2 - Generic AI-Driven Pipeline

Accepts input text (URL, SMS, email, text), expands short/obfuscated URLs,
runs DNS, IP, WHOIS, VirusTotal, AbuseIPDB, and Groq/Gemini AI brain in parallel.
Never 500s on any service failure.
"""

import logging
import asyncio
import httpx
from typing import Dict, Any, List
from fastapi import APIRouter, UploadFile, File, Form
from pydantic import BaseModel

log = logging.getLogger(__name__)

from app.utils.extractor import extract_all, extract_domain_from_url
from app.services.dns_service import enrich_dns
from app.services.ip_service import enrich_ip
from app.services.ai_brain import analyze_ai_brain
from app.services.whois_service import check_domain_age
from app.services.virustotal_service import check_virustotal
from app.services.abuseipdb_service import check_abuseipdb
from app.services.ml_service import predict_ml
from app.database import get_cached_scan, save_scan, get_recent_scans
from app.utils.final_scoring import calculate_final_score

router = APIRouter(tags=["Analysis"])


class AnalyzeRequest(BaseModel):
    text: str


@router.get("/history")
async def get_scan_history(limit: int = 10):
    """Fetch recent scans from SQLite database."""
    scans = get_recent_scans(limit=limit)
    return {"status": "success", "count": len(scans), "scans": scans}


async def _expand_url(url: str) -> str:
    """Expand shortened/obfuscated URL by following redirects (4s timeout)."""
    if not url:
        return ""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=4.0, headers={"User-Agent": "PhishGuard/3.2"}) as client:
            resp = await client.head(url)
            if resp.status_code >= 400:
                resp = await client.get(url)
            return str(resp.url)
    except Exception as e:
        log.debug(f"[URL Expand Note] Could not expand {url}: {e}")
        return url


@router.post("/analyze")
async def analyze_input(payload: AnalyzeRequest):
    """
    Main analysis endpoint using generic 3-layer architecture.
    """
    text = payload.text.strip()
    if not text:
        return {"error": "Please enter text to analyze"}

    # ── Step 1: Check SQLite Cache ──
    cached_result = get_cached_scan(text)
    if cached_result:
        return cached_result

    # ── Step 2: Generic Extractor ──
    extracted = extract_all(text)
    primary_domain = extracted.get("primary_domain")
    primary_url = extracted.get("primary_url")
    final_url = primary_url

    # Expand obfuscated/shortened URLs if detected
    if extracted.get("has_obfuscation") and primary_url:
        expanded = await _expand_url(primary_url)
        if expanded and expanded != primary_url:
            final_url = expanded
            expanded_domain = extract_domain_from_url(expanded)
            if expanded_domain:
                primary_domain = expanded_domain
                extracted["primary_domain"] = expanded_domain
                if expanded_domain not in extracted["domains"]:
                    extracted["domains"].append(expanded_domain)

    # ── Step 3: Parallel Layer B (Enrichers) + Layer C (AI Brain) ──
    async def _safe_dns() -> Dict[str, Any]:
        try:
            return await enrich_dns(primary_domain)
        except Exception as e:
            log.warning(f"[DNS Service Error]: {e}")
            return {"is_applicable": False, "risk": 0, "status": "DNS Lookup Failed", "checks": {}}

    async def _safe_ip() -> Dict[str, Any]:
        try:
            return await enrich_ip(primary_domain or (extracted["ips"][0] if extracted["ips"] else None))
        except Exception as e:
            log.warning(f"[IP Service Error]: {e}")
            return {"is_applicable": False, "risk": 0, "status": "IP Lookup Failed"}

    async def _safe_whois() -> Dict[str, Any]:
        if not primary_domain:
            return {"domain": "", "age_days": None, "risk": 0, "reason": "No domain"}
        try:
            return await asyncio.to_thread(check_domain_age, primary_domain)
        except Exception as e:
            log.warning(f"[WHOIS Service Error]: {e}")
            return {"domain": primary_domain, "age_days": None, "risk": 0, "reason": "WHOIS Lookup Failed"}

    async def _safe_vt() -> Dict[str, Any]:
        target = primary_url or primary_domain
        if not target:
            return {"malicious": 0, "suspicious": 0, "risk": 0}
        try:
            return await asyncio.wait_for(check_virustotal(target), timeout=6.0)
        except Exception as e:
            log.warning(f"[VirusTotal Error]: {e}")
            return {"malicious": 0, "suspicious": 0, "risk": 0}

    async def _safe_abuse() -> Dict[str, Any]:
        target = (extracted["ips"][0] if extracted["ips"] else None) or primary_domain
        if not target:
            return {"confidence": 0, "risk": 0}
        try:
            return await asyncio.wait_for(check_abuseipdb(target), timeout=6.0)
        except Exception as e:
            log.warning(f"[AbuseIPDB Error]: {e}")
            return {"confidence": 0, "risk": 0}

    async def _safe_ai() -> Dict[str, Any]:
        try:
            return await analyze_ai_brain(text, extracted)
        except Exception as e:
            log.warning(f"[AI Brain Error]: {e}")
            return {"is_phishing": False, "confidence": 0, "risk_score": 0, "attack_vector": "Legitimate", "reason": "AI Error"}

    # Execute all 6 services concurrently
    dns_res, ip_res, whois_res, vt_res, abuse_res, ai_res = await asyncio.gather(
        _safe_dns(), _safe_ip(), _safe_whois(), _safe_vt(), _safe_abuse(), _safe_ai()
    )

    # ── Step 4: Final AI-Driven Composite Scoring ──
    scoring = calculate_final_score(extracted, dns_res, ip_res, whois_res, vt_res, abuse_res, ai_res)

    # Legacy detection flow list for UI stepper
    detection_flow = [
        {"layer": "Generic Extractor", "status": "completed", "findings": len(extracted["urls"]) + len(extracted["emails"])},
        {"layer": "DNS Security", "status": "completed", "status_text": dns_res.get("status")},
        {"layer": "IP Intelligence", "status": "completed", "isp": ip_res.get("isp")},
        {"layer": "WHOIS Domain Age", "status": "completed", "age_days": whois_res.get("age_days")},
        {"layer": "Threat Intelligence (VT & AbuseIPDB)", "status": "completed"},
        {"layer": "AI Threat Engine (Groq / Gemini)", "status": "completed", "is_phishing": ai_res.get("is_phishing")},
    ]

    # Legacy breakdown mapping for frontend UI cards
    legacy_breakdown = {
        "rule": scoring["breakdown"]["ai"],
        "url": scoring["breakdown"]["obfuscation"],
        "ai": scoring["breakdown"]["ai"],
        "dns": scoring["breakdown"]["dns"],
        "ip": scoring["breakdown"]["ip"],
        "whois": scoring["breakdown"]["whois"],
        "vt": scoring["breakdown"]["vt"],
        "abuse": scoring["breakdown"]["abuse"],
        "harvester": 0,
        "wfuzz": 0,
        "total": scoring["score"]
    }

    response_payload = {
        "score": scoring["score"],
        "risk_score": scoring["score"],
        "composite_score": scoring["score"],
        "risk_level": scoring["risk_level"],
        "threat_level": scoring["risk_level"],
        "attack_vector": scoring["attack_vector"],
        "attack_type": scoring["attack_vector"].lower().replace(" ", "_"),
        "dns_status": dns_res.get("status", "Unknown"),
        "final_url": final_url,
        "extracted": extracted,
        "breakdown": legacy_breakdown,
        "urls_found": extracted["urls"],
        "ips_found": extracted["ips"],
        "dns": dns_res,
        "ip_details": ip_res,
        "whois": whois_res,
        "virustotal": vt_res,
        "abuseipdb": abuse_res,
        "ai_result": {
            "is_phishing": ai_res.get("is_phishing", False),
            "confidence": ai_res.get("confidence", 0),
            "risk_level": scoring["risk_level"],
            "attack_type": scoring["attack_vector"],
            "reasons": ai_res.get("indicators", [ai_res.get("reason")]),
        },
        "risk_factors": ai_res.get("indicators", [ai_res.get("reason")]),
        "detection_flow": detection_flow,
        "cached": False
    }

    # ── Step 5: Cache in SQLite ──
    save_scan(text, scoring["score"], response_payload, scoring["score"] >= 35)

    return response_payload


from app.services.ocr_service import scan_image as ocr_scan_image
from app.services.gemini_service import analyze_image_vision


@router.post("/analyze-image")
async def analyze_image_endpoint(image: UploadFile = File(None), text: str = Form("")):
    """
    Image Analysis Endpoint for EasyOCR + Gemini Vision text extraction.
    """
    extracted_text = ""
    if image:
        try:
            contents = await image.read()
            mime_type = image.content_type or "image/png"
            if contents:
                extracted_text = ocr_scan_image(contents).strip()
                if not extracted_text:
                    vision_res = await analyze_image_vision(contents, mime_type=mime_type)
                    extracted_text = vision_res.get("extracted_text", "").strip()
        except Exception as e:
            log.error(f"[Analyze Image Error]: {e}")

    if not extracted_text and text and text.strip():
        extracted_text = text.strip()

    if not extracted_text:
        return {"error": "No text extracted from image.", "extracted_text": ""}

    payload = AnalyzeRequest(text=extracted_text)
    res = await analyze_input(payload)
    res["extracted_text"] = extracted_text
    return res
