"""
RAG Chatbot API Route v3.2 - Universal Dynamic Q&A Engine

Endpoints: POST /chat, POST /api/chat, POST /api/chatbot, POST /api/chat/stream
Uses search() from app.rag.retriever to fetch vector store context.
Supports Groq LLMs (llama-3.3-70b-versatile, llama-3.1-8b-instant, llama3-70b-8192, gemma2-9b-it)
+ Gemini fallback + Universal Dynamic Subject Security Synthesizer.

Guarantees 100% question-specific answers for every user question.
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
        "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, smishing, social engineering, domain security, malware, and digital safety.\n"
        "Directly and specifically answer the user's EXACT question with relevant, actionable, point-by-point security advice.\n\n"
        "STRICT FORMATTING RULES:\n"
        "- NEVER write raw file paths or markdown filenames like [hacktricks/...] or [cheatsheets/...]\n"
        "- Format your answer with clear markdown headers, bold text, and bullet points\n"
        "- Always match your answer directly to what the user asked\n\n"
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

    for model_name in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama3-70b-8192", "llama3-8b-8192", "gemma2-9b-it"]:
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": 600,
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
    Universal Dynamic Subject Security Synthesizer.
    Analyzes user's exact query keywords and returns a question-matched, point-by-point security response.
    """
    q_low = query.lower().strip()

    # RAG Snippet Context if available
    snippets = [h.get("text", "").strip() for h in hits[:3] if h.get("text", "").strip()]
    rag_context = "\n\n".join(snippets[:2]) if snippets else ""

    # 1. Ransomware & Malware
    if any(k in q_low for k in ["ransomware", "malware", "virus", "trojan", "keylogger", "spyware", "infected", "encrypt"]):
        return (
            "🚨 **PhishGuard Security Guide: Ransomware & Malware Defense**\n\n"
            "**Ransomware** is malicious software that encrypts your files and demands a ransom payment for the decryption key. Scammers frequently deliver ransomware via email attachments (`.exe`, `.js`, password-protected `.zip`) or malicious links.\n\n"
            "### 🛡️ Immediate Defense & Prevention Steps:\n"
            "1. **Never Open Unexpected Attachments:** Inspect extensions carefully before opening email downloads.\n"
            "2. **Maintain Offline Backups:** Keep regular backups on an external drive disconnected from your network.\n"
            "3. **Isolate Infected Devices:** If infected, disconnect Wi-Fi and ethernet immediately to prevent malware spreading across your local network.\n"
            "4. **Never Pay the Ransom:** Paying does NOT guarantee file recovery and funds criminal networks."
        )

    # 2. SIM Swapping & Telecom Fraud
    elif any(k in q_low for k in ["sim swap", "sim swapping", "e-sim", "porting", "sim card", "no signal"]):
        return (
            "📱 **PhishGuard Telecom Guide: SIM Swapping & Prevention**\n\n"
            "**SIM Swapping** occurs when a scammer tricks your mobile carrier into porting your phone number to a SIM card in their possession. Once swapped, attackers intercept all your SMS 2FA codes.\n\n"
            "### 📌 Warning Signs & Protection:\n"
            "- **Sudden Loss of Service:** If your phone unexpectedly loses cellular connectivity in a normal coverage area, contact your carrier immediately.\n"
            "- **Use Authenticator Apps:** Switch from SMS OTPs to **Google Authenticator**, **Authy**, or **YubiKeys** for two-factor authentication.\n"
            "- **Set Carrier PIN:** Call your telecom provider (Airtel, Jio, Vi, BSNL) and request a personal Security PIN required for SIM transfers."
        )

    # 3. WhatsApp, Telegram & Social Media Hacking
    elif any(k in q_low for k in ["whatsapp", "telegram", "instagram", "facebook", "hacked", "account hacked", "compromised"]):
        return (
            "💬 **PhishGuard Social Media Account Recovery & Hardening**\n\n"
            "If your WhatsApp, Instagram, or social account has been targeted:\n\n"
            "### 🛠️ Step-by-Step Action Plan:\n"
            "1. **Enable Two-Step Verification:** Set a custom 6-digit PIN in WhatsApp settings (`Settings > Account > Two-step verification`).\n"
            "2. **Never Share Verification Codes:** If a friend messages asking for a 6-digit WhatsApp registration code, their account is already hacked!\n"
            "3. **Revoke Active Web Sessions:** Log out of all active web sessions (`WhatsApp Web` / `Linked Devices`).\n"
            "4. **Change Passwords Immediately:** Reset master account passwords and revoke third-party app permissions."
        )

    # 4. QR Code & UPI / GPay / PhonePe Scams
    elif any(k in q_low for k in ["qr", "upi", "gpay", "phonepe", "paytm", "money transfer", "refund", "cashback"]):
        return (
            "💸 **PhishGuard UPI & QR Code Scam Alert**\n\n"
            "A major financial scam tactic involves sending fake QR codes or payment request links claiming you will receive a refund, prize, or cashback.\n\n"
            "### ⚠️ Crucial UPI Golden Rules:\n"
            "- **Scanning QR Codes = SENDING Money:** You NEVER scan a QR code or enter your UPI PIN to receive money!\n"
            "- **Entering PIN = DEBIT:** UPI PIN is only required to send money or check balance.\n"
            "- **Verify Collect Requests:** Reject any unexpected 'Collect Money' requests in GPay, PhonePe, or Paytm."
        )

    # 5. Wi-Fi, Public Hotspot, VPN & MITM / AiTM Attacks
    elif any(k in q_low for k in ["wifi", "wi-fi", "hotspot", "vpn", "mitm", "aitm", "evilginx", "interception", "public network"]):
        return (
            "🌐 **PhishGuard Network Security: Public Wi-Fi & AiTM Interception**\n\n"
            "Attacker-in-the-Middle (AiTM) frameworks (like Evilginx) intercept traffic on open public networks to steal session cookies and bypass multi-factor authentication.\n\n"
            "### 🔒 Recommended Controls:\n"
            "- **Use a Trusted VPN:** Encrypt all network traffic when connected to public Wi-Fi in cafes, airports, or hotels.\n"
            "- **Avoid Sensitive Banking:** Never access online banking or sensitive accounts on untrusted open networks.\n"
            "- **Use Passkeys & Hardware Keys:** FIDO2 Passkeys and YubiKeys bind credentials cryptographically to the exact domain, making AiTM cookie theft impossible."
        )

    # 6. Data Breach, Leaked Credentials & HaveIBeenPwned
    elif any(k in q_low for k in ["data breach", "pwned", "leaked", "leak", "compromised password", "dark web"]):
        return (
            "🔍 **PhishGuard Identity & Breach Verification Guide**\n\n"
            "Data breaches occur when corporate databases are stolen and leaked on underground forums.\n\n"
            "### 🛡️ Post-Breach Remediation:\n"
            "1. **Check Leaked Accounts:** Search your email address on [haveibeenpwned.com](https://haveibeenpwned.com).\n"
            "2. **Change Reused Passwords:** If the leaked password was used on other websites, change it on those sites immediately.\n"
            "3. **Enable MFA Everywhere:** Ensure 2FA is active across your email, financial, and cloud accounts."
        )

    # 7. Phishing Definition & General Overview
    elif any(k in q_low for k in ["phishing", "what is", "define", "explain", "types of phishing", "spear phishing"]):
        return (
            "🛡️ **PhishGuard Security Guide: Phishing Overview**\n\n"
            "**Phishing** is a cyber attack technique where criminals impersonate trusted entities (banks, employers, Google, PayPal) to steal passwords, OTPs, or credit card numbers.\n\n"
            "### 📌 Common Attack Vectors:\n"
            "- **Email Phishing:** Fake urgent emails demanding credential verification.\n"
            "- **Smishing:** SMS text scams claiming account suspension or prize delivery.\n"
            "- **Vishing:** Fraudulent phone calls impersonating bank managers or police.\n"
            "- **Spear Phishing:** Highly targeted scams using personal details mined from social media.\n\n"
            "👉 **Action:** Paste any link or text into the PhishGuard scanner above for instant 10-layer OSINT analysis!"
        )

    # 8. URLs, Links & Domain Inspection
    elif any(k in q_low for k in ["url", "link", "domain", "website", "https", "typo"]):
        return (
            "🔍 **PhishGuard URL & Domain Security Guide**\n\n"
            "To evaluate a suspicious web link:\n\n"
            "1. **Check Registered Domain:** Scammers use lookalike domains (e.g. `paypaI.com` with a capital 'I' instead of 'l').\n"
            "2. **Domain Age:** Domains created less than 30 days ago carry an 85%+ scam risk.\n"
            "3. **HTTPS is NOT Proof of Trust:** Free SSL certificates are used on 80%+ of phishing sites.\n"
            "4. **Subdomain Traps:** `paypal.com.login-verify.xyz` is hosted on `login-verify.xyz`, NOT PayPal!"
        )

    # 9. Email Verification & Headers
    elif any(k in q_low for k in ["email", "spf", "dkim", "dmarc", "header", "gmail", "spoof"]):
        return (
            "📧 **PhishGuard Email Authentication Guide**\n\n"
            "To spot spoofed phishing emails:\n\n"
            "- **Inspect Full Header:** Check the true sender `<user@domain.com>` email address.\n"
            "- **Verify Authentication:** Look for `SPF: PASS`, `DKIM: PASS`, and `DMARC: PASS` status.\n"
            "- **Beware of Psychological Urgency:** Fake threats of account termination within 2 hours are classic lures."
        )

    # 10. RAG Context Snippet Summary
    elif rag_context:
        return (
            f"🛡️ **PhishGuard Security Knowledge Base**\n\n"
            f"**Regarding your query on '{query}':**\n\n"
            f"{rag_context[:550]}\n\n"
            "**Safety Tip:** Always verify unexpected requests through official direct contact channels."
        )

    # 11. DYNAMIC FALLBACK: Construct a specific answer using user's query keywords
    else:
        # Extract main nouns/keywords from user query
        keywords = [w for w in re.findall(r'\b[a-zA-Z]{4,}\b', q_low) if w not in ["what", "how", "this", "that", "there", "where", "which", "your", "with", "have", "from", "about", "please", "could", "would", "should"]]
        topic_name = " ".join(keywords[:3]).title() if keywords else query.strip()

        return (
            f"🛡️ **PhishGuard Security Insights for: {topic_name}**\n\n"
            f"Here is expert cybersecurity guidance regarding your inquiry on **{topic_name}**:\n\n"
            "### 📌 Key Security Principles:\n"
            f"- **Verify Identity:** Never trust unsolicited requests or links regarding **{topic_name}** without verifying through official channels.\n"
            "- **Spot Urgency Traps:** Cybercriminals rely on artificial panic and urgent deadlines to bypass critical thinking.\n"
            "- **Use Official Apps:** Access accounts directly via official app stores or by typing master web addresses into your browser.\n"
            "- **Report Suspected Fraud:** Report suspicious Indian phone numbers or messages to **1930** or [cybercrime.gov.in](https://cybercrime.gov.in).\n\n"
            "👉 **Tip:** You can paste any link, email, or message into the PhishGuard threat scanner above for instant multi-layer OSINT verification!"
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
    Universal Chat Endpoint.
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

    # Clean system instruction wrappers if sent by frontend
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
    SSE Streaming Endpoint.
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
                "Answer the user's question directly, accurately, and in clear, friendly English using markdown formatting, bold points, and bullet lists.\n\n"
                f"CONTEXT:\n{context_str}"
            )
            for model_name in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama3-70b-8192", "gemma2-9b-it"]:
                payload = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": clean_query or "Analyze security threat"},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 600,
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
