"""
RAG Chatbot API Route v3.2
Endpoints: POST /chat, POST /api/chat, POST /api/chatbot, POST /api/chat/stream
Uses search() from app.rag.retriever to fetch top k=5 vector store chunks
Injects context into Groq (llama-3.3-70b-versatile / llama-3.1-8b-instant / llama3-8b-8192)
with Gemini fallback and an intelligent multi-topic security knowledge engine fallback.
"""

import asyncio
import base64
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.config import GEMINI_API_KEY, GEMINI_MODEL, GROQ_API_KEY

log = logging.getLogger(__name__)
router = APIRouter(tags=["Chatbot"])

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def clean_llm_answer(text: str) -> str:
    """Strip hallucinated source blocks & clean formatting."""
    if not text:
        return text
    text = re.split(r'📚', text, flags=re.IGNORECASE)[0]
    text = re.split(r'Knowledge Sources:', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\*\*Knowledge Sources\*\*', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\nSources:', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\n\*\*Sources', text, flags=re.IGNORECASE)[0]
    
    text = re.sub(r'\[.*?\.md\]', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\[.*?\.(md|txt)\]', '', text, flags=re.IGNORECASE)
    
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        low = line.lower()
        if any(x in low for x in ['license.md', 'xamarin', 'mach-o', 'wasm-', 'pre-training', 'universal-binaries']):
            continue
        if low.strip().endswith('.md') and ('/' in low or '\\' in low):
            continue
        cleaned.append(line)
    text = '\n'.join(cleaned)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


class ChatRequest(BaseModel):
    message: str = ""


async def _call_groq_text(query: str, hits: List[Dict[str, Any]]) -> Optional[str]:
    """Call Groq API with system prompt and hits context."""
    groq_key = os.getenv("GROQ_API_KEY", GROQ_API_KEY or "").strip()
    if not groq_key or groq_key == "your_groq_api_key_here":
        return None

    context_parts = [h.get("text", "") for h in hits if h.get("text")]
    context_str = "\n\n---\n\n".join(context_parts) if context_parts else "No extra context."

    system_prompt = (
        "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, smishing, social engineering, domain security, and digital safety.\n"
        "Answer the user's question directly, accurately, and in clear, friendly English using markdown formatting, bold points, and bullet lists.\n\n"
        "STRICT FORMATTING RULES:\n"
        "- NEVER write raw file paths or markdown filenames like [hacktricks/...] or [cheatsheets/...]\n"
        "- Give clean, direct answers with bullet points\n"
        "- Keep answers concise, highly informative, and easy to read\n\n"
        f"CONTEXT (if relevant):\n{context_str}"
    )

    headers = {
        "Authorization": f"Bearer {groq_key}",
        "Content-Type": "application/json",
        "User-Agent": "PhishGuard/3.2",
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query},
    ]

    for model_name in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama3-8b-8192"]:
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": 512,
            "temperature": 0.3,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(GROQ_URL, json=payload, headers=headers)
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    if content and len(content.strip()) > 5:
                        return content.strip()
        except Exception as exc:
            log.warning(f"[Groq Chat] Model {model_name} failed: {exc}")
            continue

    return None


async def _call_gemini_fallback(query: str, hits: List[Dict[str, Any]], image_b64: Optional[str] = None, mime: Optional[str] = None) -> Optional[str]:
    """Gemini fallback if Groq API is unavailable."""
    gemini_key = os.getenv("GEMINI_API_KEY", GEMINI_API_KEY or "").strip()
    if not gemini_key:
        return None

    context_parts = [h.get('text', '') for h in hits if h.get('text')]
    context_str = "\n\n---\n\n".join(context_parts) if context_parts else "No extra context."

    system_prompt = (
        "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, smishing, social engineering, domain security, and digital safety.\n"
        "Answer the user's question directly, accurately, and in clear, friendly English.\n\n"
        f"CONTEXT (if relevant):\n{context_str}"
    )

    parts: List[Dict[str, Any]] = [{"text": f"{system_prompt}\n\nUser Question: {query}"}]
    if image_b64 and mime:
        parts.append({"inline_data": {"mime_type": mime, "data": image_b64}})

    contents = [{"parts": parts}]
    models = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"]
    headers = {"Content-Type": "application/json", "User-Agent": "PhishGuard/3.2"}

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json={"contents": contents}, headers=headers)
                if res.status_code == 200:
                    candidates = res.json().get("candidates", [])
                    if candidates:
                        parts_out = candidates[0].get("content", {}).get("parts", [])
                        if parts_out:
                            text_out = parts_out[0].get("text", "")
                            if text_out and len(text_out.strip()) > 5:
                                return text_out.strip()
        except Exception as exc:
            log.warning(f"[Gemini Fallback Exception ({model})]: {exc}")
            continue
    return None


def _build_rag_rule_fallback(query: str, hits: List[Dict[str, Any]]) -> str:
    """
    Rich Intelligent Local Security Engine Fallback.
    Provides comprehensive, detailed markdown answers when external LLM API keys are offline.
    """
    q_low = query.lower()
    snippets = []
    for h in hits[:3]:
        t = h.get("text", "").strip()
        if t and len(t) > 20:
            snippets.append(t)

    context_summary = "\n\n".join(snippets[:2]) if snippets else ""

    # Topic 1: Phishing Definition & Concepts
    if any(k in q_low for k in ["what is phishing", "phishing mean", "define phishing", "explain phishing", "types of phishing"]):
        return (
            "🛡️ **PhishGuard Security Guide: What is Phishing?**\n\n"
            "**Phishing** is a form of social engineering where cybercriminals impersonate legitimate organizations (like banks, PayPal, Google, or government portals) to trick you into revealing sensitive information such as passwords, OTPs, credit card details, or banking credentials.\n\n"
            "### 📌 Common Types of Phishing:\n"
            "- **Email Phishing:** Fake emails claiming your account is suspended or urgent action is required.\n"
            "- **Smishing (SMS Phishing):** Fake text messages with urgent links (e.g. reward claims, KYC updates, package tracking).\n"
            "- **Vishing (Voice Phishing):** Fraudulent phone calls claiming to be from bank security or law enforcement.\n"
            "- **Spear Phishing:** Targeted attacks directed at specific individuals using personalized information.\n\n"
            "### 🛡️ How to Stay Protected:\n"
            "1. **Never Click Unverified Links:** Always type official web addresses manually.\n"
            "2. **Verify Urgency Claims:** Contact official customer support through verified phone numbers.\n"
            "3. **Use Multi-Factor Authentication (MFA):** Prefer authenticator apps over SMS OTPs."
        )

    # Topic 2: URLs, Links, Domain & Typosquatting
    elif any(k in q_low for k in ["url", "link", "domain", "website", "https", "check link", "typosquatting", "safe"]):
        return (
            "🔍 **PhishGuard URL & Domain Security Inspection Guide**\n\n"
            "When evaluating suspicious web links:\n\n"
            "1. **Inspect Domain Spelling:** Watch out for typosquatting (e.g. `paypaI.com` using uppercase 'I' instead of 'l', or `google-security-verify.net`).\n"
            "2. **Check Domain Age:** Scammers register new domains right before launching campaigns. Domains younger than 30 days carry an 85%+ risk.\n"
            "3. **HTTPS Alone is NOT Enough:** Over 80% of phishing sites use free SSL certificates (HTTPS). HTTPS encrypts traffic but does not guarantee identity.\n"
            "4. **Subdomain Masking:** Check the actual registered domain (e.g. `paypal.com.scamdomain.xyz` is hosted on `scamdomain.xyz`, NOT PayPal).\n\n"
            "👉 **Tip:** Paste any link directly into the **PhishGuard Threat Scanner** above for real-time OSINT analysis!"
        )

    # Topic 3: Smishing, Banking, OTP & SMS Fraud
    elif any(k in q_low for k in ["sms", "smishing", "text", "otp", "bank", "upi", "gpay", "phone", "lottery", "kyc"]):
        return (
            "📱 **PhishGuard Smishing & Banking Scam Guide**\n\n"
            "Smishing uses urgent SMS messages to steal OTPs or trick you into visiting fraudulent banking portals.\n\n"
            "### ⚠️ Critical Safety Rules:\n"
            "- **Banks Never Request OTPs:** No legitimate bank or service provider will ever ask for OTPs or PINs over the phone or via SMS.\n"
            "- **QR Code Scams:** Scanning a QR code in GPay, PhonePe, or Paytm **DEBITS** money from your account. You NEVER enter your PIN to receive money!\n"
            "- **KYC & Reward Traps:** Messages threatening SIM block or electricity disconnection within 2 hours are 100% scam campaigns.\n\n"
            "🚨 **Report Fraud Immediately:** Call **1930** (Indian National Cyber Crime Helpline) or report at [cybercrime.gov.in](https://cybercrime.gov.in)."
        )

    # Topic 4: Email Headers, SPF, DKIM, DMARC
    elif any(k in q_low for k in ["email", "spf", "dkim", "dmarc", "header", "gmail", "spoof"]):
        return (
            "📧 **PhishGuard Email Verification & Authentication Guide**\n\n"
            "Attackers can easily spoof the display name in an email. To verify authenticity:\n\n"
            "1. **Check Full Sender Address:** Click the sender details to view the full `<user@domain.com>` email address.\n"
            "2. **Verify Email Authentication:**\n"
            "   - **SPF (Sender Policy Framework):** Verifies the sending server's IP is authorized.\n"
            "   - **DKIM (DomainKeys Identified Mail):** Validates digital signatures to ensure body content was not altered.\n"
            "   - **DMARC:** Enforces policies when SPF or DKIM fail.\n"
            "3. **Beware of Suspicious Attachments:** Never download `.exe`, `.scr`, or password-protected `.zip` files from unexpected senders."
        )

    # Topic 5: Social Engineering & Password Safety
    elif any(k in q_low for k in ["password", "mfa", "social engineering", "vishing", "urgency", "security"]):
        return (
            "🔐 **PhishGuard Password & Social Engineering Safety**\n\n"
            "### 💡 Key Security Practices:\n"
            "- **Unique Passwords:** Use a password manager to maintain unique, complex passwords for every service.\n"
            "- **Authenticator Apps over SMS:** Switch to Google Authenticator, Authy, or Passkeys to prevent SIM swap attacks.\n"
            "- **Golden Hour Protocol:** If you suspect your credentials were compromised, change your password immediately and revoke active sessions."
        )

    # Topic 6: Knowledge Base Context Summary (if RAG hits present)
    elif context_summary:
        return (
            f"🛡️ **PhishGuard Security Knowledge Base**\n\n"
            f"{context_summary[:500]}\n\n"
            "**Safety Tip:** Always verify unrequested messages through official, direct contact channels."
        )

    # Topic 7: Generic High-Quality Default Assistant Response
    else:
        return (
            "🛡️ **PhishGuard Security Assistant**\n\n"
            "I'm here to help you identify and prevent digital threats including phishing, smishing, domain spoofing, and online fraud.\n\n"
            "### 🚀 How You Can Use PhishGuard:\n"
            "- **Scan Suspicious Links & Texts:** Paste any URL, email, or message into the main threat scanner above.\n"
            "- **Phone Number OSINT:** Enter any mobile number to view approximate telecom circle and carrier info.\n"
            "- **Ask Questions:** Ask me about link safety, OTP fraud, email verification, or reporting scams to **1930** / [cybercrime.gov.in](https://cybercrime.gov.in)."
        )


@router.post("/chat")
@router.post("/api/chat")
@router.post("/api/chatbot")
async def chat_endpoint(
    request: Request,
    message: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
):
    """
    RAG-enabled Chat Endpoint.
    """
    user_query = ""
    image_b64 = None
    mime_type = None
    has_image = False

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            user_query = body.get("message", "").strip()
        except Exception:
            user_query = ""
    else:
        if message:
            user_query = message.strip()
        if image and image.filename:
            raw = await image.read()
            if len(raw) <= 5 * 1024 * 1024:
                image_b64 = base64.b64encode(raw).decode("utf-8")
                mime_type = image.content_type or "image/png"
                has_image = True

    # Strip system instructions if sent by frontend wrapper
    if "User Question:" in user_query:
        clean_query = user_query.split("User Question:")[-1].strip()
    else:
        clean_query = user_query

    if not clean_query and not has_image:
        return {"reply": "Please enter a question or upload an image.", "sources": []}

    # 1. Search vector store
    from app.rag.retriever import search  # noqa: PLC0415
    hits = search(clean_query, k=5) if clean_query else []

    confidence = "high" if len(hits) >= 4 else "medium" if len(hits) >= 2 else "low"
    has_evilginx = any("evilginx" in h.get("text", "").lower() or "aitm" in h.get("text", "").lower() for h in hits)
    risk = "high" if has_evilginx else "medium" if "phish" in clean_query.lower() else "low"

    q_low = clean_query.lower()
    if "mitm" in q_low:
        suggestions = ["How to prevent MITM?", "What is AiTM phishing?", "How does Evilginx bypass MFA?", "MITM vs AiTM difference?"]
    elif "phish" in q_low:
        suggestions = ["What is spear phishing?", "How to detect phishing email?", "What is D3FEND detection for phishing?", "Phishing prevention best practices?"]
    elif "evilginx" in q_low or "aitm" in q_low:
        suggestions = ["How to detect AiTM?", "How does session hijacking work?", "MFA bypass prevention?"]
    else:
        suggestions = ["Explain phishing types", "How to prevent phishing?", "What is MITM attack?"]

    raw_sources = [h["source"] for h in hits if "source" in h]
    sources = []
    for src in raw_sources:
        parts = src.split("/")
        short_src = "/".join(parts[-2:]) if len(parts) >= 2 else src
        if short_src not in sources:
            sources.append(short_src)

    # 2. Query LLMs with fallbacks
    reply = await _call_groq_text(clean_query, hits)

    if not reply:
        reply = await _call_gemini_fallback(clean_query or "Analyze security threat", hits, image_b64, mime_type)

    if not reply:
        reply = _build_rag_rule_fallback(clean_query, hits)

    reply = clean_llm_answer(reply)

    return {
        "reply": reply,
        "sources": sources,
        "confidence": confidence,
        "risk": risk,
        "suggestions": suggestions,
        "hits_count": len(hits),
        "has_evilginx": has_evilginx,
    }


@router.post("/chat/stream")
@router.post("/api/chat/stream")
@router.post("/api/chatbot/stream")
async def chat_stream_endpoint(
    request: Request,
    message: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
):
    """
    RAG-enabled SSE Streaming Endpoint.
    """
    user_query = ""
    image_b64 = None
    mime_type = None
    has_image = False

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            user_query = body.get("message", "").strip()
        except Exception:
            user_query = ""
    else:
        if message:
            user_query = message.strip()
        if image and image.filename:
            raw = await image.read()
            if len(raw) <= 5 * 1024 * 1024:
                image_b64 = base64.b64encode(raw).decode("utf-8")
                mime_type = image.content_type or "image/png"
                has_image = True

    if "User Question:" in user_query:
        clean_query = user_query.split("User Question:")[-1].strip()
    else:
        clean_query = user_query

    from app.rag.retriever import search  # noqa: PLC0415
    hits = search(clean_query, k=5) if clean_query else []

    raw_sources = [h["source"] for h in hits if "source" in h]
    sources = []
    for src in raw_sources:
        parts = src.split("/")
        short_src = "/".join(parts[-2:]) if len(parts) >= 2 else src
        if short_src not in sources:
            sources.append(short_src)

    confidence = "high" if len(hits) >= 4 else "medium" if len(hits) >= 2 else "low"
    has_evilginx = any("evilginx" in h.get("text", "").lower() or "aitm" in h.get("text", "").lower() for h in hits)
    risk = "high" if has_evilginx else "medium" if "phish" in clean_query.lower() else "low"

    q_low = clean_query.lower()
    if "mitm" in q_low:
        suggestions = ["How to prevent MITM?", "What is AiTM phishing?", "How does Evilginx bypass MFA?", "MITM vs AiTM difference?"]
    elif "phish" in q_low:
        suggestions = ["What is spear phishing?", "How to detect phishing email?", "What is D3FEND detection for phishing?", "Phishing prevention best practices?"]
    elif "evilginx" in q_low or "aitm" in q_low:
        suggestions = ["How to detect AiTM?", "How does session hijacking work?", "MFA bypass prevention?"]
    else:
        suggestions = ["Explain phishing types", "How to prevent phishing?", "What is MITM attack?"]

    async def generate():
        meta = {
            "type": "meta",
            "confidence": confidence,
            "risk": risk,
            "sources": sources,
            "suggestions": suggestions,
            "hits_count": len(hits),
            "has_evilginx": has_evilginx,
        }
        yield f"data: {json.dumps(meta)}\n\n"

        streamed_success = False
        groq_key = os.getenv("GROQ_API_KEY", GROQ_API_KEY or "").strip()

        if groq_key and groq_key != "your_groq_api_key_here":
            headers = {
                "Authorization": f"Bearer {groq_key}",
                "Content-Type": "application/json",
                "User-Agent": "PhishGuard/3.2",
            }
            context_parts = [h.get("text", "") for h in hits]
            context_str = "\n\n---\n\n".join(context_parts)
            system_prompt = (
                "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, smishing, social engineering, domain security, and digital safety.\n"
                "Answer the user's question directly, accurately, and in clear, friendly English.\n\n"
                f"CONTEXT:\n{context_str}"
            )
            for model_name in ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]:
                payload = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": clean_query or "Analyze security threat"},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 512,
                    "stream": True,
                }
                try:
                    full_reply = ""
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        async with client.stream("POST", GROQ_URL, json=payload, headers=headers) as resp:
                            if resp.status_code == 200:
                                async for line in resp.aiter_lines():
                                    if line.startswith("data: "):
                                        data_str = line[6:].strip()
                                        if data_str == "[DONE]":
                                            streamed_success = True
                                            break
                                        try:
                                            chunk_json = json.loads(data_str)
                                            delta = chunk_json["choices"][0]["delta"].get("content", "")
                                            if delta:
                                                full_reply += delta
                                                yield f"data: {json.dumps({'type': 'token', 'content': delta})}\n\n"
                                        except Exception:
                                            continue
                    if streamed_success:
                        break
                except Exception as exc:
                    log.warning(f"[Groq Stream] Model {model_name} streaming failed: {exc}")
                    continue

        if not streamed_success:
            fallback_text = await _call_gemini_fallback(clean_query or "Analyze threat", hits, image_b64, mime_type)
            if not fallback_text:
                fallback_text = _build_rag_rule_fallback(clean_query, hits)

            fallback_text = clean_llm_answer(fallback_text)

            for char_chunk in [fallback_text[i:i + 12] for i in range(0, len(fallback_text), 12)]:
                yield f"data: {json.dumps({'type': 'token', 'content': char_chunk})}\n\n"
                await asyncio.sleep(0.01)

        yield f"data: {json.dumps({'type': 'done', 'suggestions': suggestions})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")
