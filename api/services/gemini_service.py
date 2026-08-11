"""
Gemini AI Reasoning & Chat Service for Vercel Engine
Uses REST API calls to Google Gemini API.
"""

import asyncio
import json
import logging
import os
import re
import httpx
from typing import Any, Dict

log = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

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
Output ONLY valid JSON."""

HTTP_TIMEOUT_SEC = 4.0


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
        "reasons": ["AI reasoning response unparseable."],
        "error": "JSON parse error",
    }


async def analyze_with_gemini(original_text: str) -> Dict[str, Any]:
    """
    Query Gemini for phishing analysis using pure httpx REST calls.
    """
    fallback: Dict[str, Any] = {
        "is_phishing": False,
        "risk_level": "LOW",
        "attack_type": "unknown",
        "social_engineering_detected": False,
        "reasons": ["AI reasoning temporarily unavailable."],
        "error": None,
    }

    if not GEMINI_API_KEY:
        fallback["error"] = "Gemini API key not configured"
        return fallback

    models_to_try = [
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
    ]

    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{SYSTEM_PROMPT}\n\nAnalyze this text for phishing:\n\n{original_text}"}
                    ]
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [])[0].get("text", "")
                        return _parse_ai_response(text)
        except Exception as exc:
            log.warning("[Gemini Analysis Exception]: %s", exc)

    return fallback


async def chat_with_gemini(message: str) -> Dict[str, Any]:
    """
    Interactive safety chatbot response generator.
    """
    if not message:
        return {"response": "Please enter a message."}

    if GEMINI_API_KEY:
        models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
        prompt = (
            "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, smishing, social engineering, domain security, and digital safety.\n"
            "Answer the user's question directly, accurately, and in clear, friendly English.\n\n"
            f"User Question: {message}"
        )
        for model in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
            payload = {
                "contents": [
                    {
                        "parts": [{"text": prompt}]
                    }
                ]
            }
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates:
                            reply = candidates[0].get("content", {}).get("parts", [])[0].get("text", "")
                            if reply.strip():
                                return {"response": reply.strip()}
            except Exception as e:
                log.warning("[Gemini Chat Exception]: %s", e)

    return {
        "response": f"PhishGuard AI Security Recommendation for: '{message[:60]}...'\n\n"
                    "• Always check the sender's full email address or domain for subtle typosquatting.\n"
                    "• Never click unknown links asking for credentials or financial actions.\n"
                    "• Legitimate organizations will never demand urgent payments via gift cards or cryptos."
    }
