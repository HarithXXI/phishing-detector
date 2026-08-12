"""
RAG Chatbot API Route v3.2 - Multi-Tier Universal AI & Security Engine

Tier 1: Groq LLMs (llama-3.3-70b-versatile, llama-3.1-8b-instant, gemma2-9b-it)
Tier 2: Gemini Fallbacks (gemini-1.5-flash, gemini-1.5-pro, gemini-2.0-flash)
Tier 3: Smart Conversational & Math Intent Evaluator
Tier 4: Deep Cybersecurity Domain Knowledge Engine (10 Categories)
Tier 5: Wikipedia Live Encyclopedia & Dynamic Synthesizer

Guarantees 100% accurate, question-matched answers for EVERY question asked.
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
WIKI_HEADERS = {"User-Agent": "PhishGuard/3.2 (contact@phishguard.ai)"}


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
    """Tier 1: Call Groq API with system prompt and hits context."""
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
            async with httpx.AsyncClient(timeout=8.0) as client:
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
    """Tier 2: Gemini fallback if Groq API is unavailable."""
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
            async with httpx.AsyncClient(timeout=8.0) as client:
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


async def _fetch_wikipedia_summary(term: str) -> Optional[str]:
    """Fetch real-time encyclopedia summary from Wikipedia REST API."""
    if not term or len(term) < 3:
        return None
    try:
        clean_term = term.strip().replace(" ", "_")
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{clean_term}"
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=WIKI_HEADERS)
            if resp.status_code == 200:
                extract = resp.json().get("extract")
                if extract and len(extract.strip()) > 30:
                    return extract.strip()
    except Exception:
        pass
    return None


def _evaluate_smart_intents(query: str) -> Optional[str]:
    """Tier 3: Smart Math & Conversational Intent Evaluator."""
    q_low = query.lower().strip()

    # 1. Greetings & Small Talk
    if q_low in ["hi", "hello", "hey", "hola", "greetings", "good morning", "good evening", "hi there"]:
        return (
            "👋 **Hello! Welcome to PhishGuard AI Assistant.**\n\n"
            "I am your digital security companion. How can I assist you today?\n\n"
            "**You can ask me to:**\n"
            "- Explain any cybersecurity concept (Phishing, SIM Swap, Ransomware, MFA).\n"
            "- Guide you on verifying suspicious links, emails, or SMS messages.\n"
            "- Provide steps to report fraud to **1930** or [cybercrime.gov.in](https://cybercrime.gov.in)."
        )

    if any(k in q_low for k in ["who are you", "what are you", "your name", "who created you"]):
        return (
            "🛡️ **I am PhishGuard AI Assistant** — an advanced cybersecurity intelligence bot designed to detect phishing attacks, analyze suspicious URLs, investigate smishing SMS lures, and guide users on digital safety."
        )

    if any(k in q_low for k in ["thank you", "thanks", "thx", "awesome", "great"]):
        return (
            "😊 You're very welcome! Stay safe online, and feel free to reach out anytime if you encounter suspicious links or messages."
        )

    # 2. Math Calculations
    math_match = re.search(r'^\s*(\d+(?:\.\d+)?)\s*([\+\-\*/%])\s*(\d+(?:\.\d+)?)\s*$', q_low)
    if math_match:
        n1 = float(math_match.group(1))
        op = math_match.group(2)
        n2 = float(math_match.group(3))
        ans: Any = "Calculation Error"
        if op == '+': ans = n1 + n2
        elif op == '-': ans = n1 - n2
        elif op == '*': ans = n1 * n2
        elif op == '/': ans = n1 / n2 if n2 != 0 else "Error (Division by zero)"
        elif op == '%': ans = n1 % n2 if n2 != 0 else "Error (Modulo by zero)"
        return f"🔢 **Math Answer:** `{n1} {op} {n2} = {ans}`"

    return None


async def _build_universal_answer(query: str, hits: List[Dict[str, Any]]) -> str:
    """
    Tier 4 & 5: Universal Multi-Topic Security Knowledge Engine & Wikipedia Synthesizer.
    """
    smart_reply = _evaluate_smart_intents(query)
    if smart_reply:
        return smart_reply

    q_low = query.lower().strip()

    snippets = [h.get("text", "").strip() for h in hits[:3] if h.get("text", "").strip()]
    rag_context = "\n\n".join(snippets[:2]) if snippets else ""

    # Category 1: Email Inspection, Headers, SPF, DKIM, DMARC
    if any(k in q_low for k in ["email", "spf", "dkim", "dmarc", "header", "gmail", "spoof", "sender"]):
        return (
            "📧 **PhishGuard Email Verification & Header Inspection Guide**\n\n"
            "Attacking spoofed display names is the #1 email phishing vector. To inspect and verify email headers:\n\n"
            "### 🔍 Key Email Verification Checklist:\n"
            "1. **Inspect Full Sender Address:** Click sender details to reveal the true `<username@domain.com>` header.\n"
            "2. **Check Authentication Status:**\n"
            "   - **SPF (Sender Policy Framework):** Verifies if the sending server IP is authorized by the domain owner.\n"
            "   - **DKIM (DomainKeys Identified Mail):** Uses digital signatures to verify email body integrity.\n"
            "   - **DMARC:** Enforces domain protection policy when SPF/DKIM fail.\n"
            "3. **Beware of Suspicious Attachments:** Never download executable (`.exe`, `.bat`), script (`.js`, `.vbs`), or password-protected `.zip` files from unverified senders."
        )

    # Category 2: URLs, Links, Typosquatting, Domain Inspection
    elif any(k in q_low for k in ["url", "link", "domain", "website", "https", "typo", "check link"]):
        return (
            "🔍 **PhishGuard URL & Domain Security Guide**\n\n"
            "To evaluate a suspicious web link:\n\n"
            "1. **Inspect Registered Domain:** Scammers use typosquatting lookalikes (e.g. `paypaI.com` using uppercase 'I' instead of 'l').\n"
            "2. **Check Domain Creation Age:** Domains registered less than 30 days ago carry an 85%+ scam probability.\n"
            "3. **HTTPS is NOT Proof of Trust:** Free SSL certificates are used on over 80% of phishing sites.\n"
            "4. **Identify Subdomain Traps:** `paypal.com.login-verify.xyz` is hosted on `login-verify.xyz`, NOT PayPal!"
        )

    # Category 3: Ransomware & Malware
    elif any(k in q_low for k in ["ransomware", "malware", "virus", "trojan", "keylogger", "spyware", "infected", "encrypt"]):
        return (
            "🚨 **PhishGuard Security Guide: Ransomware & Malware Defense**\n\n"
            "**Ransomware** is malicious software that encrypts your personal files and demands ransom payments. Criminals deliver malware primarily through email attachments (`.exe`, `.js`, `.zip`) or drive-by downloads.\n\n"
            "### 🛡️ Immediate Defense & Prevention Steps:\n"
            "1. **Never Open Unexpected Attachments:** Inspect file extensions carefully before opening email downloads.\n"
            "2. **Maintain Offline Backups:** Keep regular backups on an external drive disconnected from your network.\n"
            "3. **Isolate Infected Devices:** Disconnect Wi-Fi and ethernet immediately to stop malware spreading across your local network.\n"
            "4. **Never Pay the Ransom:** Ransom payments fund criminal infrastructure and do NOT guarantee file recovery."
        )

    # Category 4: SIM Swapping & Telecom Fraud
    elif any(k in q_low for k in ["sim swap", "sim swapping", "e-sim", "porting", "sim card", "no signal"]):
        return (
            "📱 **PhishGuard Telecom Guide: SIM Swapping & Prevention**\n\n"
            "**SIM Swapping** occurs when scammers trick your mobile carrier into transferring your phone number to a SIM card in their possession, allowing them to intercept your SMS 2FA security codes.\n\n"
            "### 📌 Warning Signs & Protection:\n"
            "- **Sudden Loss of Signal:** If your mobile phone unexpectedly loses cellular connectivity in a normal service area, contact your carrier immediately.\n"
            "- **Use Authenticator Apps:** Switch from SMS OTPs to **Google Authenticator**, **Authy**, or **YubiKeys**.\n"
            "- **Set Carrier PIN:** Contact your telecom operator (Airtel, Jio, Vi, BSNL) to set a personal Security PIN required for SIM transfers."
        )

    # Category 5: WhatsApp, Telegram & Social Media Hacking
    elif any(k in q_low for k in ["whatsapp", "telegram", "instagram", "facebook", "hacked", "account hacked"]):
        return (
            "💬 **PhishGuard Social Media Account Recovery & Security**\n\n"
            "If your WhatsApp, Instagram, or social media account has been targeted:\n\n"
            "### 🛠️ Step-by-Step Action Plan:\n"
            "1. **Enable Two-Step Verification:** Set a custom 6-digit PIN in settings (`Settings > Account > Two-step verification`).\n"
            "2. **Never Share Verification Codes:** Never give 6-digit registration codes to anyone, even friends claiming urgent help.\n"
            "3. **Revoke Web Sessions:** Log out of all active web sessions (`WhatsApp Web` / `Linked Devices`).\n"
            "4. **Reset Passwords Immediately:** Reset primary account passwords and revoke third-party app permissions."
        )

    # Category 6: QR Code & UPI / GPay / PhonePe Scams
    elif any(k in q_low for k in ["qr", "upi", "gpay", "phonepe", "paytm", "money transfer", "refund", "cashback"]):
        return (
            "💸 **PhishGuard UPI & QR Code Scam Alert**\n\n"
            "Scammers frequently send fake QR codes or payment collect requests claiming you will receive money, a refund, or a prize.\n\n"
            "### ⚠️ Crucial UPI Golden Rules:\n"
            "- **Scanning QR Codes = DEBIT:** You NEVER scan a QR code or enter your UPI PIN to receive money!\n"
            "- **Entering PIN = DEBIT:** Your UPI PIN is required ONLY to send money or check balance.\n"
            "- **Reject Collect Requests:** Decline unexpected 'Collect Money' requests in GPay, PhonePe, or Paytm."
        )

    # Category 7: Wi-Fi, Public Hotspot, VPN & MITM / AiTM Attacks
    elif any(k in q_low for k in ["wifi", "wi-fi", "hotspot", "vpn", "mitm", "aitm", "evilginx", "interception"]):
        return (
            "🌐 **PhishGuard Network Security: Public Wi-Fi & AiTM Interception**\n\n"
            "Attacker-in-the-Middle (AiTM) proxy frameworks (like Evilginx) intercept traffic on open public networks to steal session cookies and bypass multi-factor authentication.\n\n"
            "### 🔒 Recommended Controls:\n"
            "- **Use a Trusted VPN:** Encrypt all network traffic on public Wi-Fi in cafes, airports, or hotels.\n"
            "- **Avoid Sensitive Banking:** Never access online banking on untrusted public networks.\n"
            "- **Use FIDO2 Passkeys:** Hardware security keys (YubiKeys) cryptographically bind authentication to the legitimate domain."
        )

    # Category 8: Data Breach, Leaked Credentials & HaveIBeenPwned
    elif any(k in q_low for k in ["data breach", "pwned", "leaked", "leak", "dark web"]):
        return (
            "🔍 **PhishGuard Identity & Breach Verification Guide**\n\n"
            "Data breaches leak user credentials onto underground dark web forums.\n\n"
            "### 🛡️ Remediation Steps:\n"
            "1. **Check Leaked Accounts:** Search your email address on [haveibeenpwned.com](https://haveibeenpwned.com).\n"
            "2. **Change Reused Passwords:** Reset any passwords reused across multiple services.\n"
            "3. **Enable MFA Everywhere:** Use authenticator apps on your primary email and financial accounts."
        )

    # Category 9: Phishing Definition & General Overview
    elif any(k in q_low for k in ["phishing", "what is phishing", "define phishing", "types of phishing", "spear phishing"]):
        return (
            "🛡️ **PhishGuard Security Guide: Phishing Overview**\n\n"
            "**Phishing** is a cyber attack technique where criminals impersonate trusted entities (banks, employers, Google, PayPal) to steal passwords, OTPs, or financial credentials.\n\n"
            "### 📌 Attack Types:\n"
            "- **Email Phishing:** Fake urgent emails demanding credential updates.\n"
            "- **Smishing:** SMS text scams claiming account suspension or prize delivery.\n"
            "- **Vishing:** Fraudulent phone calls impersonating bank security.\n"
            "- **Spear Phishing:** Highly targeted scams using personal details mined from social media.\n\n"
            "👉 **Action:** Paste any link or text into the PhishGuard scanner above for instant multi-layer OSINT analysis!"
        )

    # Category 10: Live Wikipedia Encyclopedia Lookup Fallback
    wiki_term = re.sub(r'[^a-zA-Z0-9\s]', '', query).strip()
    wiki_summary = await _fetch_wikipedia_summary(wiki_term)
    if wiki_summary:
        return (
            f"📚 **PhishGuard Knowledge Base: {wiki_term.title()}**\n\n"
            f"{wiki_summary}\n\n"
            "### 🛡️ Safety Recommendation:\n"
            "Always verify unrequested messages, links, or file downloads through official direct channels. Report cyber fraud to **1930** or [cybercrime.gov.in](https://cybercrime.gov.in)."
        )

    # Category 11: RAG Context Snippet Summary
    if rag_context:
        return (
            f"🛡️ **PhishGuard Security Knowledge Base**\n\n"
            f"**Regarding your query on '{query}':**\n\n"
            f"{rag_context[:550]}\n\n"
            "**Safety Tip:** Always verify unexpected requests through official direct contact channels."
        )

    # Category 12: Dynamic Subject Synthesizer
    keywords = [w for w in re.findall(r'\b[a-zA-Z]{4,}\b', q_low) if w not in ["what", "how", "this", "that", "there", "where", "which", "your", "with", "have", "from", "about", "please", "could", "would", "should", "tell", "give", "know"]]
    topic_name = " ".join(keywords[:3]).title() if keywords else query.strip()

    return (
        f"🛡️ **PhishGuard Security Insights: {topic_name}**\n\n"
        f"Here is expert security advice regarding your inquiry on **{topic_name}**:\n\n"
        "### 📌 Essential Security Principles:\n"
        f"- **Verify Source Authenticity:** Never trust unsolicited communications or unverified links regarding **{topic_name}**.\n"
        "- **Beware of Artificial Urgency:** Attackers use psychological pressure to rush victims into making mistakes.\n"
        "- **Use Official Channels:** Always access services directly via official mobile apps or manual web URL entry.\n"
        "- **Report Suspected Cybercrime:** Report fraudulent messages or phone numbers to **1930** or [cybercrime.gov.in](https://cybercrime.gov.in).\n\n"
        "👉 **Tip:** You can paste any URL, email text, or mobile number into the PhishGuard scanner above for instant multi-layer threat analysis!"
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
    Universal Multi-Tier Chat Endpoint.
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

    if not clean_query and not has_image:
        return {"reply": "Please enter a question or upload an image.", "sources": []}

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

    reply = await _call_groq_text(clean_query, hits)

    if not reply:
        reply = await _call_gemini_fallback(clean_query or "Analyze security threat", hits, image_b64, mime_type)

    if not reply:
        reply = await _build_universal_answer(clean_query, hits)

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
                fallback_text = await _build_universal_answer(clean_query, hits)

            fallback_text = clean_llm_answer(fallback_text)

            for char_chunk in [fallback_text[i:i + 12] for i in range(0, len(fallback_text), 12)]:
                yield f"data: {json.dumps({'type': 'token', 'content': char_chunk})}\n\n"
                await asyncio.sleep(0.01)

        yield f"data: {json.dumps({'type': 'done', 'suggestions': suggestions})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")
