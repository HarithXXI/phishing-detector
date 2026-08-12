"""
AI Brain Service v3.2 - Groq LLM Primary + Gemini Fallback

Analyzes input text (SMS, URL, email, text) using LLM reasoning.
Returns structured JSON with risk score (0-40), confidence (0-100), attack vector, and indicators.
No hardcoded brand keyword rules.
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# Try importing Groq
try:
    from groq import Groq
    _HAS_GROQ = True
except ImportError:
    _HAS_GROQ = False

from app.services.gemini_service import analyze_with_gemini

SYSTEM_PROMPT = """You are PhishGuard AI Threat Engine. Analyze ANY user input (could be URL, SMS, email, scam text, or legitimate input).
Return ONLY valid raw JSON with NO markdown formatting, NO code blocks, NO triple backticks:
{"is_phishing": bool, "confidence": 85, "attack_vector": "Phishing Link / Scam Text / Legitimate", "reason": "Short summary of finding", "risk_score": 0, "indicators": ["reason 1", "reason 2"]}

Evaluation Rules:
1. Consider: urgency, financial rewards, account suspension/blocked claims, suspicious/obfuscated URLs, mismatched domains, grammar anomalies, requests to click link, credential harvesting lures.
2. If input is legitimate (e.g. google.com, paypal.com, github.com, or benign text) -> is_phishing: false, risk_score: 0, attack_vector: "Legitimate".
3. If input lures user to click suspicious link, verify account, or claim prize -> is_phishing: true, risk_score: 30-40, attack_vector: appropriate vector name.
4. Be completely generic and brand-agnostic.
"""


from typing import Dict, Any, Optional

async def analyze_ai_brain(text: str, extracted_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Main AI reasoning function with Groq -> Gemini -> Clean Fallback.
    Never crashes, always returns dict with risk_score (0-40).
    """
    text = (text or "").strip()
    if not text:
        return {
            "is_phishing": False,
            "confidence": 0,
            "risk_score": 0,
            "attack_vector": "Legitimate",
            "reason": "Empty input text",
            "indicators": []
        }

    groq_api_key = (os.getenv("GROQ_API_KEY") or "").strip()

    # ── Strategy 1: Groq LLM Primary ──
    if _HAS_GROQ and groq_api_key and groq_api_key != "your_groq_api_key_here":
        try:
            def _call_groq():
                client = Groq(api_key=groq_api_key)
                response = client.chat.completions.create(
                    model="llama3-8b-8192",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze this input text:\n{text}"}
                    ],
                    temperature=0.1,
                    max_tokens=350,
                )
                return response.choices[0].message.content

            raw_resp = await asyncio.wait_for(asyncio.to_thread(_call_groq), timeout=6.0)
            
            # Clean json formatting
            cleaned_resp = (raw_resp or "").strip()
            if cleaned_resp.startswith("```"):
                cleaned_resp = cleaned_resp.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            if cleaned_resp.startswith("json"):
                cleaned_resp = cleaned_resp[4:].strip()

            parsed = json.loads(cleaned_resp)
            return {
                "is_phishing": bool(parsed.get("is_phishing", False)),
                "confidence": int(parsed.get("confidence", 50)),
                "risk_score": min(40, max(0, int(parsed.get("risk_score", 0)))),
                "attack_vector": str(parsed.get("attack_vector", "Suspicious Pattern")),
                "reason": str(parsed.get("reason", "AI threat analysis completed.")),
                "indicators": list(parsed.get("indicators", []))
            }
        except Exception as exc:
            log.warning("[AI Brain Groq Warning] %s", exc)

    # ── Strategy 2: Gemini LLM Fallback ──
    try:
        gemini_res = await asyncio.wait_for(analyze_with_gemini(text), timeout=6.0)
        is_phish = gemini_res.get("is_phishing", False)
        risk_lvl = gemini_res.get("risk_level", "LOW")
        
        risk_score = 35 if is_phish or risk_lvl in ["HIGH", "CRITICAL"] else (15 if risk_lvl == "MEDIUM" else 0)
        attack_vec = gemini_res.get("attack_type", "generic_phishing").replace("_", " ").title()
        if not is_phish and risk_score == 0:
            attack_vec = "Legitimate"

        return {
            "is_phishing": is_phish,
            "confidence": 80 if is_phish else 90,
            "risk_score": risk_score,
            "attack_vector": attack_vec,
            "reason": gemini_res.get("reasons", ["AI analysis completed."])[0] if gemini_res.get("reasons") else "Gemini verified intent.",
            "indicators": gemini_res.get("reasons", [])
        }
    except Exception as exc:
        log.warning("[AI Brain Gemini Warning] %s", exc)

    # ── Strategy 3: Safe Default Fallback (No Crash) ──
    return {
        "is_phishing": False,
        "confidence": 0,
        "risk_score": 0,
        "attack_vector": "Legitimate",
        "reason": "AI reasoning service currently unavailable",
        "indicators": []
    }
