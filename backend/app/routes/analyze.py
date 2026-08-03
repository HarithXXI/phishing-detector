"""
Analysis Route

POST /analyze — Orchestrates all four detection layers concurrently
with strict timeouts (8s VT/AbuseIPDB, 10s Gemini) so slow APIs never block.
"""

import logging
import re
import asyncio
from fastapi import APIRouter
from pydantic import BaseModel

log = logging.getLogger(__name__)

from app.services.rule_engine import check_rules
from app.services.url_heuristic import check_url_heuristics
from app.services.virustotal_service import check_virustotal
from app.services.abuseipdb_service import check_abuseipdb
from app.services.gemini_service import analyze_with_gemini
from app.utils.scoring import calculate_composite_score

router = APIRouter(tags=["Analysis"])


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
    Main analysis endpoint. Runs all 4 detection layers concurrently.
    Enforces strict 8s timeout for VirusTotal & AbuseIPDB, and 10s for Gemini.
    """
    text = payload.text.strip()
    print(f"[API ANALYZE ENDPOINT] Received request (len={len(text)}): '{text[:60]}...'")

    if not text:
        return {"error": "Please enter text"}

    detection_flow = []

    # ── Layer 1: Rule Engine (synchronous, instant) ──
    rule_risks = check_rules(text)
    detection_flow.append({
        "layer": "Rule-Based Engine",
        "status": "completed",
        "findings": len(rule_risks),
    })

    # ── Layer 2: URL Heuristics (synchronous, instant) ──
    url_risks, extracted_urls = check_url_heuristics(text)
    detection_flow.append({
        "layer": "URL Heuristic Engine",
        "status": "completed",
        "findings": len(url_risks),
        "urls_found": len(extracted_urls),
    })

    # ── Layer 3 & 4: Threat Intel + AI (concurrent in parallel with strict timeouts) ──
    extracted_ips = _extract_ips(text)

    # 1. VirusTotal Task (8s hard cap)
    async def _safe_vt() -> dict:
        try:
            return await asyncio.wait_for(_run_virustotal(extracted_urls, text), timeout=8.0)
        except asyncio.TimeoutError:
            log.warning("[VT] Request timed out after 8s")
            return {"malicious": 0, "suspicious": 0, "error": "VirusTotal request timed out (8s limit)"}
        except Exception as exc:
            log.exception("[VT] Exception: %s", exc)
            return {"malicious": 0, "suspicious": 0, "error": f"VirusTotal error: {exc}"}

    # 2. AbuseIPDB Task (8s hard cap)
    async def _safe_abuse() -> dict:
        try:
            return await asyncio.wait_for(_run_abuseipdb(extracted_ips, extracted_urls, text), timeout=8.0)
        except asyncio.TimeoutError:
            log.warning("[AbuseIPDB] Request timed out after 8s")
            return {"abuseConfidenceScore": 0, "totalReports": 0, "risk_score": 5, "error": "AbuseIPDB request timed out (8s limit)"}
        except Exception as exc:
            log.exception("[AbuseIPDB] Exception: %s", exc)
            return {"abuseConfidenceScore": 0, "totalReports": 0, "risk_score": 5, "error": f"AbuseIPDB error: {exc}"}

    # 3. Gemini AI Task (10s hard cap)
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
                "reasons": ["AI reasoning timed out (10s limit). Relying on VirusTotal and AbuseIPDB."],
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

    # Run all 3 external checks in parallel concurrently
    vt_result, abuse_result, ai_result = await asyncio.gather(
        _safe_vt(), _safe_abuse(), _safe_ai()
    )

    log.info(
        "[VT] Result → malicious=%d suspicious=%d total_vendors=%d vt_risk=%d error=%s",
        vt_result.get("malicious", 0),
        vt_result.get("suspicious", 0),
        vt_result.get("total_vendors", 0),
        vt_result.get("vt_risk_score", 5),
        vt_result.get("error"),
    )

    detection_flow.append({
        "layer": "Threat Intelligence",
        "status": "completed",
        "virustotal": {
            "malicious":       vt_result.get("malicious", 0),
            "suspicious":      vt_result.get("suspicious", 0),
            "harmless":        vt_result.get("harmless", 0),
            "total_vendors":   vt_result.get("total_vendors", 0),
            "vendors_flagged": vt_result.get("vendors_flagged", []),
            "reputation":      vt_result.get("reputation", 0),
            "vt_risk_score":   vt_result.get("vt_risk_score", 5),
            "error":           vt_result.get("error"),
        },
        "abuseipdb": {
            "ipAddress":            abuse_result.get("ipAddress"),
            "abuseConfidenceScore": abuse_result.get("abuseConfidenceScore", 0),
            "totalReports":         abuse_result.get("totalReports", 0),
            "country":              abuse_result.get("country"),
            "isp":                  abuse_result.get("isp"),
            "lastReportedAt":       abuse_result.get("lastReportedAt"),
            "isWhitelisted":        abuse_result.get("isWhitelisted", False),
            "risk_score":           abuse_result.get("risk_score", 5),
            "error":                abuse_result.get("error"),
        },
    })

    detection_flow.append({
        "layer": "AI Reasoning (Gemini)",
        "status": "completed",
        "is_phishing": ai_result.get("is_phishing", False),
        "attack_type": ai_result.get("attack_type", "unknown"),
        "error": ai_result.get("error"),
    })

    # ── Scoring ──
    scoring = calculate_composite_score(
        rule_risks=rule_risks,
        url_risks=url_risks,
        vt_result=vt_result,
        abuse_result=abuse_result,
        ai_result=ai_result,
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

    return {
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
        "virustotal": {
            "malicious":       vt_result.get("malicious", 0),
            "suspicious":      vt_result.get("suspicious", 0),
            "harmless":        vt_result.get("harmless", 0),
            "total_vendors":   vt_result.get("total_vendors", 0),
            "vendors_flagged": vt_result.get("vendors_flagged", []),
            "reputation":      vt_result.get("reputation", 0),
            "vt_risk_score":   vt_result.get("vt_risk_score", 5),
            "error":           vt_result.get("error"),
        },
        "abuseipdb": {
            "ipAddress":            abuse_result.get("ipAddress"),
            "abuseConfidenceScore": abuse_result.get("abuseConfidenceScore", 0),
            "totalReports":         abuse_result.get("totalReports", 0),
            "country":              abuse_result.get("country"),
            "isp":                  abuse_result.get("isp"),
            "lastReportedAt":       abuse_result.get("lastReportedAt"),
            "isWhitelisted":        abuse_result.get("isWhitelisted", False),
            "risk_score":           abuse_result.get("risk_score", 5),
            "error":                abuse_result.get("error"),
        },
        "ai_result": {
            "is_phishing": ai_result.get("is_phishing", False),
            "risk_level": ai_result.get("risk_level", "LOW"),
            "attack_type": final_attack_type,
            "social_engineering_detected": ai_result.get("social_engineering_detected", False),
            "reasons": ai_result.get("reasons", []),
        },
        "detection_flow": detection_flow,
    }


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
