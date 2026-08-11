"""
Analysis Route

POST /analyze — Orchestrates all four detection layers concurrently
with strict timeouts (8s VT/AbuseIPDB, 10s Gemini) so slow APIs never block.
"""

import logging
import re
import asyncio
from fastapi import APIRouter, UploadFile, File, Form
from pydantic import BaseModel

log = logging.getLogger(__name__)

from app.services.rule_engine import check_rules
from app.services.url_heuristic import check_url_heuristics
from app.services.virustotal_service import check_virustotal
from app.services.abuseipdb_service import check_abuseipdb
from app.services.gemini_service import analyze_with_gemini, analyze_image_vision
from app.services.whois_service import check_domain_age
from app.services.ml_service import predict_ml
from app.database import get_cached_scan, save_scan, get_recent_scans
from app.utils.scoring import calculate_composite_score

router = APIRouter(tags=["Analysis"])


@router.get("/history")
async def get_scan_history(limit: int = 10):
    """Fetch recent scans from SQLite database."""
    scans = get_recent_scans(limit=limit)
    return {"status": "success", "count": len(scans), "scans": scans}


class AnalyzeRequest(BaseModel):
    text: str


def _extract_ips(text: str) -> list[str]:
    """Pull valid IPv4 addresses from text."""
    return re.findall(
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        text,
    )


def _extract_urls(text: str) -> list[str]:
    """Pull URLs and bare domains from text."""
    full_urls = re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
    if full_urls:
        return full_urls

    bare_domains = re.findall(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|gov|edu|io|info|work|site|online|tech|app|xyz|top|live|me|co|in|ly)(?:/[^\s<>\"']*)?\b",
        text,
        re.IGNORECASE,
    )
    return [f"https://{d}" if not d.startswith("http") else d for d in bare_domains]


@router.post("/analyze")
async def analyze_input(payload: AnalyzeRequest):
    """
    Main analysis endpoint. Checks SQLite cache first, then runs all 6 detection layers.
    """
    text = payload.text.strip()
    print(f"[API ANALYZE ENDPOINT] Received request (len={len(text)}): '{text[:60]}...'")

    if not text:
        return {"error": "Please enter text"}

    # ── Check SQLite Cache First ──
    cached_result = get_cached_scan(text)
    if cached_result:
        return cached_result

    detection_flow = []

    # ── Layer 1: Rule Engine ──
    rule_risks = check_rules(text)
    detection_flow.append({
        "layer": "Rule-Based Engine",
        "status": "completed",
        "findings": len(rule_risks),
    })

    # ── Layer 2: URL Heuristics ──
    url_risks, extracted_urls = check_url_heuristics(text)
    detection_flow.append({
        "layer": "URL Heuristic Engine",
        "status": "completed",
        "findings": len(url_risks),
        "urls_found": len(extracted_urls),
    })

    # ── Layer 3: WHOIS Domain Age & Layer 4: ML Prediction (Instant) ──
    target_domain = extracted_urls[0] if extracted_urls else (text if len(text) < 100 and "." in text and not " " in text else "")
    whois_res = check_domain_age(target_domain) if target_domain else {"domain": "", "age_days": None, "creation_date": None, "risk": "LOW", "score": 0, "reason": "No domain found"}
    ml_res = predict_ml(target_domain) if target_domain else {"is_phishing": False, "ml_score": 0, "confidence": 0, "model": "ML Ensemble", "reasons": []}

    detection_flow.append({
        "layer": "WHOIS Domain Age Service",
        "status": "completed",
        "domain": whois_res.get("domain"),
        "age_days": whois_res.get("age_days"),
        "risk": whois_res.get("risk"),
    })

    detection_flow.append({
        "layer": "ML Model Ensemble (Random Forest + XGBoost)",
        "status": "completed",
        "ml_score": ml_res.get("ml_score"),
        "model": ml_res.get("model"),
    })

    # ── Layer 5 & 6: Threat Intel + AI (concurrent in parallel) ──
    extracted_ips = _extract_ips(text)

    async def _safe_vt() -> dict:
        try:
            return await asyncio.wait_for(_run_virustotal(extracted_urls, text), timeout=8.0)
        except asyncio.TimeoutError:
            log.warning("[VT] Request timed out after 8s")
            return {"malicious": 0, "suspicious": 0, "error": "VirusTotal request timed out (8s limit)"}
        except Exception as exc:
            log.exception("[VT] Exception: %s", exc)
            return {"malicious": 0, "suspicious": 0, "error": f"VirusTotal error: {exc}"}

    async def _safe_abuse() -> dict:
        try:
            return await asyncio.wait_for(_run_abuseipdb(extracted_ips, extracted_urls, text), timeout=8.0)
        except asyncio.TimeoutError:
            log.warning("[AbuseIPDB] Request timed out after 8s")
            return {"abuseConfidenceScore": 0, "totalReports": 0, "risk_score": 5, "error": "AbuseIPDB request timed out (8s limit)"}
        except Exception as exc:
            log.exception("[AbuseIPDB] Exception: %s", exc)
            return {"abuseConfidenceScore": 0, "totalReports": 0, "risk_score": 5, "error": f"AbuseIPDB error: {exc}"}

    async def _safe_ai() -> dict:
        try:
            return await asyncio.wait_for(analyze_with_gemini(text), timeout=10.0)
        except asyncio.TimeoutError:
            log.warning("[Gemini] Request timed out after 10s")
            return {
                "is_phishing": False,
                "risk_level": "LOW",
                "attack_type": "unknown",
                "social_engineering_detected": False,
                "reasons": ["AI reasoning timed out."],
                "error": "Gemini API request timed out (10s limit)",
            }
        except Exception as exc:
            log.exception("[Gemini] Exception: %s", exc)
            return {
                "is_phishing": False,
                "risk_level": "LOW",
                "attack_type": "unknown",
                "social_engineering_detected": False,
                "reasons": [],
                "error": f"Gemini API error: {exc}",
            }

    vt_result, abuse_result, ai_result = await asyncio.gather(
        _safe_vt(), _safe_abuse(), _safe_ai()
    )

    detection_flow.append({
        "layer": "Threat Intelligence",
        "status": "completed",
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
    })

    detection_flow.append({
        "layer": "AI Reasoning (Gemini)",
        "status": "completed",
        "is_phishing": ai_result.get("is_phishing", False),
    })

    # ── Scoring Calculation ──
    scoring = calculate_composite_score(
        rule_risks=rule_risks,
        url_risks=url_risks,
        vt_result=vt_result,
        abuse_result=abuse_result,
        ai_result=ai_result,
        whois_result=whois_res,
        ml_result=ml_res,
    )

    # ── Attack Vector Classification ──
    raw_ai_type = (ai_result.get("attack_type") or "").lower()
    text_low = text.lower()
    all_risks_text = " ".join(rule_risks + url_risks).lower()

    if scoring["score"] == 0 and not rule_risks and not url_risks:
        final_attack_type = "clean"
    elif raw_ai_type in ["smishing", "spear_phishing", "whaling", "credential_harvesting", "brand_impersonation"]:
        final_attack_type = raw_ai_type
    elif "sms" in text_low or "frm:" in text_low or "shortener" in all_risks_text or (len(text) < 300 and ("click:" in text_low or "cutt.ly" in text_low or "bit.ly" in text_low)):
        final_attack_type = "smishing"
    elif "verification" in all_risks_text or "password" in text_low or "login" in text_low or "sign in" in text_low:
        final_attack_type = "credential_harvesting"
    elif "brand" in all_risks_text or "paypal" in text_low or "chase" in text_low or "bank" in text_low or "delivery" in text_low:
        final_attack_type = "brand_impersonation"
    elif "subject:" in text_low or "@" in text_low or len(text) > 300:
        final_attack_type = "email_phishing"
    else:
        final_attack_type = "suspicious_link" if extracted_urls else "generic_phishing"

    response_payload = {
        "score": scoring["score"],
        "composite_score": scoring["score"],
        "risk_level": scoring["risk_level"],
        "threat_level": scoring["risk_level"],
        "attack_type": final_attack_type,
        "risks": rule_risks + url_risks,
        "risk_factors": rule_risks + url_risks,
        "breakdown": scoring["breakdown"],
        "urls_found": extracted_urls,
        "ips_found": extracted_ips,
        "whois": whois_res,
        "ml_model": ml_res,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "ai_result": {
            "is_phishing": ai_result.get("is_phishing", False),
            "risk_level": ai_result.get("risk_level", "LOW"),
            "attack_type": final_attack_type,
            "social_engineering_detected": ai_result.get("social_engineering_detected", False),
            "reasons": ai_result.get("reasons", []),
        },
        "detection_flow": detection_flow,
        "cached": False
    }

    # ── Save Result to SQLite Cache ──
    save_scan(text, scoring["score"], response_payload, scoring["score"] >= 35)

    return response_payload


async def _run_virustotal(urls: list[str], text: str = "") -> dict:
    """Run VirusTotal check on target URL or raw text (supports domain extraction)."""
    target = urls[0] if urls else text
    if not target:
        return {"malicious": 0, "suspicious": 0, "error": "No URLs to scan"}

    return await check_virustotal(target)


# pyrefly: ignore [bad-function-definition]
async def _run_abuseipdb(ips: list[str], urls: list[str] = None, text: str = "") -> dict:
    """Run AbuseIPDB check on target IP, extracted URL, or raw text (supports DNS resolution)."""
    target = ips[0] if ips else (urls[0] if urls else text)
    if not target:
        return {"abuseConfidenceScore": 0, "totalReports": 0, "risk_score": 5, "error": "No IP or target to check"}

    return await check_abuseipdb(target)


from app.services.ocr_service import scan_image as ocr_scan_image


@router.post("/analyze-image")
async def analyze_image_endpoint(image: UploadFile = File(None), text: str = Form("")):
    """
    Image Analysis Endpoint for FastAPI Heavy Backend.
    Accepts uploaded file + optional client text, extracts text via EasyOCR (or Gemini Vision), and runs analysis.
    """
    extracted_text = ""

    if image:
        try:
            contents = await image.read()
            mime_type = image.content_type or "image/png"
            if contents:
                # Step 1: Run EasyOCR + OpenCV
                extracted_text = ocr_scan_image(contents).strip()

                # Step 2: Fallback to Gemini Vision API if EasyOCR returns empty
                if not extracted_text:
                    vision_res = await analyze_image_vision(contents, mime_type=mime_type)
                    extracted_text = vision_res.get("extracted_text", "").strip()
        except Exception as e:
            log.error(f"[Analyze Image Error]: {e}")

    # Step 3: Fallback to client-side text (e.g. from Tesseract.js or user input) if OCR returned empty
    if not extracted_text and text and text.strip():
        extracted_text = text.strip()

    if not extracted_text:
        return {"error": "No text extracted from image. Please enter text or try a clearer image.", "extracted_text": ""}

    # Run extracted text through 6-layer analysis
    payload = AnalyzeRequest(text=extracted_text)
    res = await analyze_input(payload)
    res["extracted_text"] = extracted_text
    return res
