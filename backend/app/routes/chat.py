"""
RAG Chatbot API Route
Endpoints: POST /chat, POST /api/chat, POST /api/chatbot
Uses search() from app.rag.retriever to fetch top k=5 vector store chunks
and injects context into Groq llama-3.3-70b-versatile.
"""

import asyncio
import base64
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.config import GEMINI_API_KEY, GEMINI_MODEL, GROQ_API_KEY

def clean_llm_answer(text: str) -> str:
    """Strip hallucinated source blocks - bulletproof version"""
    if not text:
        return text
    # Remove everything from 📚 onwards - case insensitive search
    # Use regex to catch 📚 with any spacing
    text = re.split(r'📚', text, flags=re.IGNORECASE)[0]
    text = re.split(r'Knowledge Sources:', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\*\*Knowledge Sources\*\*', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\nSources:', text, flags=re.IGNORECASE)[0]
    text = re.split(r'\n\*\*Sources', text, flags=re.IGNORECASE)[0]
    
    # Remove inline [xxx.md] citations
    text = re.sub(r'\[.*?\.md\]', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\[.*?\.(md|txt)\]', '', text, flags=re.IGNORECASE)
    # Remove leftover bullet list of .md files at end
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        low = line.lower()
        # Skip lines that are clearly source file listings
        if any(x in low for x in ['license.md', 'xamarin', 'mach-o', 'wasm-', 'pre-training', 'universal-binaries']):
            continue
        if low.strip().endswith('.md') and ('/' in low or '\\' in low):
            continue
        cleaned.append(line)
    text = '\n'.join(cleaned)
    # Clean multiple blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()
# NOTE: app.rag.retriever is NOT imported here — lazy-loaded inside endpoint

log = logging.getLogger(__name__)
router = APIRouter(tags=["Chatbot"])

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class ChatRequest(BaseModel):
    message: str = ""


async def _call_groq_text(query: str, hits: List[Dict[str, Any]]) -> Optional[str]:
    """Call Groq API llama-3.3-70b-versatile with exact system prompt and hits context."""
    if not GROQ_API_KEY:
        return None

    # Construct context string from hits - NO [repo/source] prefix to prevent model copying
    context_parts = []
    for h in hits:
        text = h.get("text", "")
        context_parts.append(text)

    context_str = "\n\n---\n\n".join(context_parts)

    system_prompt = (
        "You are a cybersecurity assistant specialized in Phishing.\n"
        "Use only the provided CONTEXT to answer.\n"
        "If CONTEXT is irrelevant, say \"I don't have relevant context for this\".\n\n"
        "STRICT RULES - YOU MUST OBEY:\n"
        "- NEVER write file paths like hacktricks/data/ or [anything.md]\n"
        "- NEVER add brackets like [hacktricks/...] or [cheatsheets/...]\n"
        "- NEVER write 'Knowledge Sources', 'Sources:', 'References', or '📚'\n"
        "- NEVER list markdown files\n"
        "- Just give clean, direct answer with bullet points\n"
        "- Keep answer concise for students\n\n"
        f"CONTEXT:\n{context_str}"
    )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "PhishGuard/1.0",
    }

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query},
    ]

    for model_name in ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]:
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": 512,
            "temperature": 0.3,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
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
    """Gemini fallback if Groq API is unavailable or rate limited."""
    context_parts = [h.get('text','') for h in hits]
    context_str = "\n\n---\n\n".join(context_parts)

    system_prompt = (
        "You are a cybersecurity assistant specialized in Phishing.\n"
        "Use only the provided CONTEXT to answer.\n"
        "If CONTEXT is irrelevant, say \"I don't have relevant context for this\".\n\n"
        "STRICT RULES - YOU MUST OBEY:\n"
        "- NEVER write file paths like hacktricks/data/ or [anything.md]\n"
        "- NEVER add brackets like [hacktricks/...] or [cheatsheets/...]\n"
        "- NEVER write 'Knowledge Sources', 'Sources:', 'References', or '📚'\n"
        "- NEVER list markdown files\n"
        "- Just give clean, direct answer with bullet points\n"
        "- Keep answer concise for students\n\n"
        f"CONTEXT:\n{context_str}"
    )

    parts: List[Dict[str, Any]] = [{"text": f"{system_prompt}\n\nUser Message: {query}"}]
    if image_b64 and mime:
        parts.append({"inline_data": {"mime_type": mime, "data": image_b64}})

    contents = [{"parts": parts}]
    models = ["gemini-flash-lite-latest", GEMINI_MODEL, "gemini-2.0-flash"]
    headers = {"Content-Type": "application/json", "User-Agent": "PhishGuard/1.0"}

    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(url, json={"contents": contents}, headers=headers)
                if res.status_code == 200:
                    candidates = res.json().get("candidates", [])
                    if candidates:
                        parts_out = candidates[0].get("content", {}).get("parts", [])
                        if parts_out:
                            text_out = parts_out[0].get("text", "")
                            if text_out and len(text_out.strip()) > 5:
                                return text_out.strip()
        except Exception:
            continue
    return None


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
    Accepts JSON body `{"message": "..."}` or Form parameters (`message`, optional `image`).
    Performs `hits = search(message, k=5)` and injects hits into Groq/Gemini prompt.
    Returns `{"reply": reply, "sources": [h['source'] for h in hits]}`.
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

    if not user_query and not has_image:
        return {"reply": "Please enter a question or upload an image.", "sources": []}

    # 1. Search vector store for top k=5 chunks (lazy load RAG to keep restart fast)
    from app.rag.retriever import search  # noqa: PLC0415
    hits = search(user_query, k=5) if user_query else []

    # Calculate confidence, evilginx detection, & risk level
    confidence = "high" if len(hits) >= 4 else "medium" if len(hits) >= 2 else "low"
    has_evilginx = any("evilginx" in h.get("text", "").lower() or "aitm" in h.get("text", "").lower() for h in hits)
    risk = "high" if has_evilginx else "medium" if "phish" in user_query.lower() else "low"

    # Dynamic suggestions based on query keywords
    q_low = user_query.lower()
    if "mitm" in q_low:
        suggestions = ["How to prevent MITM?", "What is AiTM phishing?", "How does Evilginx bypass MFA?", "MITM vs AiTM difference?"]
    elif "phish" in q_low:
        suggestions = ["What is spear phishing?", "How to detect phishing email?", "What is D3FEND detection for phishing?", "Phishing prevention best practices?"]
    elif "evilginx" in q_low or "aitm" in q_low:
        suggestions = ["How to detect AiTM?", "How does session hijacking work?", "MFA bypass prevention?"]
    else:
        suggestions = ["Explain phishing types", "How to prevent phishing?", "What is MITM attack?"]

    # 2. Extract source file paths (format as short relative paths for UI pills)
    raw_sources = [h["source"] for h in hits if "source" in h]
    sources = []
    for src in raw_sources:
        parts = src.split("/")
        short_src = "/".join(parts[-2:]) if len(parts) >= 2 else src
        if short_src not in sources:
            sources.append(short_src)

    # 3. Query LLM
    reply = await _call_groq_text(user_query, hits)

    if not reply:
        reply = await _call_gemini_fallback(user_query or "Analyze security threat", hits, image_b64, mime_type)

    if not reply:
        reply = (
            "🛡️ **PhishGuard AI Assistant**\n\n"
            "I could not reach the Groq API or Gemini model right now. "
            "Please check your API keys in `backend/.env`."
        )
    
    # 4. CLEAN - Remove any hallucinated source blocks
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
    RAG-enabled SSE Streaming Endpoint (ChatGPT-style typing effect).
    Yields data: {"type": "meta"|"token"|"done", ...}
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

    # 1. Search vector store
    from app.rag.retriever import search  # noqa: PLC0415
    hits = search(user_query, k=5) if user_query else []

    # 2. Extract metadata
    raw_sources = [h["source"] for h in hits if "source" in h]
    sources = []
    for src in raw_sources:
        parts = src.split("/")
        short_src = "/".join(parts[-2:]) if len(parts) >= 2 else src
        if short_src not in sources:
            sources.append(short_src)

    confidence = "high" if len(hits) >= 4 else "medium" if len(hits) >= 2 else "low"
    has_evilginx = any("evilginx" in h.get("text", "").lower() or "aitm" in h.get("text", "").lower() for h in hits)
    risk = "high" if has_evilginx else "medium" if "phish" in user_query.lower() else "low"

    q_low = user_query.lower()
    if "mitm" in q_low:
        suggestions = ["How to prevent MITM?", "What is AiTM phishing?", "How does Evilginx bypass MFA?", "MITM vs AiTM difference?"]
    elif "phish" in q_low:
        suggestions = ["What is spear phishing?", "How to detect phishing email?", "What is D3FEND detection for phishing?", "Phishing prevention best practices?"]
    elif "evilginx" in q_low or "aitm" in q_low:
        suggestions = ["How to detect AiTM?", "How does session hijacking work?", "MFA bypass prevention?"]
    else:
        suggestions = ["Explain phishing types", "How to prevent phishing?", "What is MITM attack?"]

    async def generate():
        # First send meta chunk
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

        # Build prompt
        context_parts = [h.get("text", "") for h in hits]
        context_str = "\n\n---\n\n".join(context_parts)
        system_prompt = (
            "You are a cybersecurity assistant specialized in Phishing.\n"
            "Use only the provided CONTEXT to answer.\n"
            "If CONTEXT is irrelevant, say \"I don't have relevant context for this\".\n\n"
            "STRICT RULES - YOU MUST OBEY:\n"
            "- NEVER write file paths like hacktricks/data/ or [anything.md]\n"
            "- NEVER add brackets like [hacktricks/...] or [cheatsheets/...]\n"
            "- NEVER write 'Knowledge Sources', 'Sources:', 'References', or '📚'\n"
            "- NEVER list markdown files\n"
            "- Just give clean, direct answer with bullet points\n"
            "- Keep answer concise for students\n\n"
            f"CONTEXT:\n{context_str}"
        )

        streamed_success = False

        if GROQ_API_KEY:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "PhishGuard/1.0",
            }
            for model_name in ["llama-3.1-8b-instant", "llama-3.3-70b-versatile"]:
                payload = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_query or "Analyze security threat"},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 512,
                    "stream": True,
                }
                try:
                    full_reply = ""
                    async with httpx.AsyncClient(timeout=30.0) as client:
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
                                                if "📚" in delta or "Knowledge Sources:" in full_reply:
                                                    break
                                                yield f"data: {json.dumps({'type': 'token', 'content': delta})}\n\n"
                                        except Exception:
                                            continue
                    if streamed_success:
                        break
                except Exception as exc:
                    log.warning(f"[Groq Stream] Model {model_name} streaming failed: {exc}")
                    continue

        # Fallback to Gemini if Groq streaming failed
        if not streamed_success:
            fallback_text = await _call_gemini_fallback(user_query or "Analyze threat", hits, image_b64, mime_type)
            if not fallback_text:
                fallback_text = (
                    "🛡️ **PhishGuard AI Assistant**\n\n"
                    "I could not reach the Groq API or Gemini model right now. "
                    "Please check your API keys in `backend/.env`."
                )
            fallback_text = clean_llm_answer(fallback_text)

            # Stream fallback text in smooth chunks
            for char_chunk in [fallback_text[i:i + 8] for i in range(0, len(fallback_text), 8)]:
                yield f"data: {json.dumps({'type': 'token', 'content': char_chunk})}\n\n"
                await asyncio.sleep(0.01)

        # Send done chunk with suggestions
        yield f"data: {json.dumps({'type': 'done', 'suggestions': suggestions})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")

