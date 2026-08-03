"""
Gemini AI Reasoning Service

Uses Google Gemini API via REST calls to perform phishing analysis.
Features strict 2-attempt max retry limit on 429 rate limits, 2s gap between retries,
and 8s request timeout so it never blocks the server or hangs the request.
"""

import asyncio
import json
import logging
import re
import httpx
from typing import Any, Dict

from app.config import GEMINI_API_KEY, GEMINI_MODEL

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a phishing detection expert. Analyze the following text and determine if it is a phishing attempt.

You MUST return a JSON object with this exact structure:
{
  "is_phishing": true/false,
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "attack_type": "phishing" or "spear_phishing" or "whaling" or "smishing" or "clean" or "suspicious",
  "social_engineering_detected": true/false,
  "reasons": ["reason 1", "reason 2"]
}

Base your decision on indicators like urgency, credential harvesting, impersonation, brand abuse, suspicious domains, and call-to-action pressure.
Output ONLY valid JSON. No markdown code blocks, no HTML, no extra commentary."""

MAX_RATE_LIMIT_RETRIES = 2
RETRY_DELAY_SEC = 2.0
HTTP_TIMEOUT_SEC = 8.0


def _parse_ai_response(raw_text: str) -> Dict[str, Any]:
    """Extract and parse JSON from raw LLM text response."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```$", "", text, flags=re.MULTILINE)
        text = text.strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    return {
        "is_phishing": False,
        "risk_level": "LOW",
        "attack_type": "unknown",
        "social_engineering_detected": False,
        "reasons": ["Failed to parse AI JSON response."],
        "error": "JSON parse error",
    }


async def analyze_with_gemini(original_text: str) -> Dict[str, Any]:
    """
    Query Gemini for phishing analysis using pure httpx REST calls.
    Iterates through model fallbacks: gemini-flash-lite-latest -> GEMINI_MODEL -> gemini-2.0-flash.
    Caps retries at 2 max on 429 rate limit with 2s delay, then returns fallback dict.
    """
    fallback: Dict[str, Any] = {
        "is_phishing": False,
        "risk_level": "LOW",
        "attack_type": "unknown",
        "social_engineering_detected": False,
        "reasons": ["AI reasoning temporarily unavailable. Relying on VirusTotal and AbuseIPDB."],
        "error": None,
    }

    if not GEMINI_API_KEY:
        log.warning("[Gemini] API key not configured")
        fallback["error"] = "Gemini API key not configured"
        return fallback

    models_to_try = [
        "gemini-flash-lite-latest",
        GEMINI_MODEL,
        "gemini-2.0-flash",
    ]

    rate_limit_attempts = 0

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PhishGuard/1.0",
    }

    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        
        payload: Dict[str, Any] = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{SYSTEM_PROMPT}\n\nAnalyze this text for phishing:\n\n{original_text}"}
                    ]
                }
            ]
        }
        if "gemma" not in model:
            payload["generationConfig"] = {"responseMimeType": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
                log.info("[Gemini] Requesting model %s...", model)
                resp = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content_parts = candidates[0].get("content", {}).get("parts", [])
                        if content_parts:
                            raw_text = content_parts[0].get("text", "")
                            parsed = _parse_ai_response(raw_text)
                            
                            parsed.setdefault("is_phishing", False)
                            parsed.setdefault("risk_level", "LOW")
                            parsed.setdefault("attack_type", "unknown")
                            parsed.setdefault("social_engineering_detected", False)
                            parsed.setdefault("reasons", [])
                            parsed["error"] = None
                            return parsed

                elif resp.status_code == 429:
                    rate_limit_attempts += 1
                    log.warning("[Gemini] Rate limit hit (429) on attempt %d/%d for model %s",
                                rate_limit_attempts, MAX_RATE_LIMIT_RETRIES, model)
                    
                    if rate_limit_attempts >= MAX_RATE_LIMIT_RETRIES:
                        log.warning("[Gemini] Reached max 429 rate limit retries (%d). Returning fallback.", MAX_RATE_LIMIT_RETRIES)
                        fallback["error"] = "Gemini API rate limit reached (429)"
                        fallback["reasons"] = ["AI reasoning temporarily unavailable due to rate limits. Relying on VirusTotal and AbuseIPDB."]
                        return fallback
                    
                    # Wait 2 seconds gap before trying next attempt
                    await asyncio.sleep(RETRY_DELAY_SEC)
                    continue

                elif resp.status_code in (404, 503):
                    log.warning("[Gemini] Model %s returned HTTP %d – trying next model", model, resp.status_code)
                    continue
                else:
                    log.error("[Gemini] HTTP %d on model %s", resp.status_code, model)
                    continue

        except httpx.TimeoutException:
            log.warning("[Gemini] Timeout (%.0fs) on model %s", HTTP_TIMEOUT_SEC, model)
            continue
        except Exception as exc:
            log.exception("[Gemini] Exception on model %s: %s", model, exc)
            continue

    fallback["error"] = "Gemini API rate limit or model unavailable"
    return fallback
