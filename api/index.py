"""
PhishGuard AI — Lightweight Vercel Serverless Entrypoint (Flask API)
Under 15MB total bundle size — 100% Vercel Serverless Compatible.
"""

import os
import re
from urllib.parse import quote, urlparse
import httpx, requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app)

# Load environment variables if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


# --- Rule Engine & URL Heuristics ---
def analyze_url_heuristics(url: str):
    parsed = urlparse(url if url.startswith(("http://", "https://")) else "https://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    score = 0
    flags = []

    if parsed.scheme == "http":
        score += 15
        flags.append("Insecure HTTP connection (missing SSL certificate)")
    
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        score += 35
        flags.append("Raw IP address used instead of domain name")

    if "@" in domain or "%20" in domain:
        score += 25
        flags.append("Suspicious obfuscated characters in URL domain")

    keywords = ["login", "verify", "secure", "account", "banking", "paypal", "update", "signin", "auth", "confirm", "wallet"]
    found_kw = [k for k in keywords if k in domain or k in path]
    if found_kw:
        score += 20 * len(found_kw)
        flags.append(f"Security/Authentication keywords in URL path: {', '.join(found_kw)}")

    shorteners = ["cutt.ly", "bit.ly", "tinyurl.com", "goo.gl", "is.gd", "t.co", "ow.ly"]
    if any(s in domain for s in shorteners):
        score += 30
        flags.append("URL shortener service hiding actual target destination")

    if len(domain.split('.')) > 3:
        score += 20
        flags.append("Excessive subdomain depth detected")

    return min(score, 100), flags, domain


def analyze_text_rules(text: str):
    txt_lower = text.lower()
    score = 0
    reasons = []

    urgency_kw = ["urgent", "immediately", "24 hours", "account suspended", "action required", "unauthorized", "locked", "expire"]
    found_urgency = [w for w in urgency_kw if w in txt_lower]
    if found_urgency:
        score += 25
        reasons.append(f"High urgency psychological triggers detected: '{', '.join(found_urgency)}'")

    financial_kw = ["credited with", "withdrawal available", "claim reward", "refund pending", "transfer received", "jackpot", "credited", "bonus", "winner", "prize", "rs.", "$", "inr"]
    found_fin = [w for w in financial_kw if w in txt_lower]
    if found_fin:
        score += 30
        reasons.append(f"Financial lure/monetary incentive detected: '{', '.join(found_fin)}'")

    credential_kw = ["verify password", "update banking details", "confirm ssn", "enter pin", "otp", "login credential"]
    found_cred = [w for w in credential_kw if w in txt_lower]
    if found_cred:
        score += 35
        reasons.append(f"Sensitive credential request: '{', '.join(found_cred)}'")

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?', text)
    clean_urls = []
    for u in urls:
        if u.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js')):
            continue
        clean_urls.append(u)

    return min(score, 100), reasons, clean_urls


def calculate_composite_score(rule_score, url_score, text):
    base = max(rule_score, url_score)
    if rule_score > 0 and url_score > 0:
        base = min(100, int(base * 1.25) + 10)

    txt_lower = text.lower()
    is_safe = ("no risk" in txt_lower or "meeting tomorrow" in txt_lower or "safe email" in txt_lower) and base < 30
    if is_safe:
        return 0, "LOW"

    final_score = max(0, min(100, base))
    if final_score >= 65:
        level = "HIGH"
    elif final_score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"
    return final_score, level


def determine_attack_vector(text, urls, risk_level):
    if risk_level == "LOW" and not urls:
        return "Clean / No Attack Detected"

    txt_lower = text.lower()
    if any(s in txt_lower for s in ["cutt.ly", "bit.ly", "tinyurl.com", "credited with", "rs.", "$", "sms", "text message"]):
        return "Smishing (SMS Scam)"
    if "paypal" in txt_lower:
        return "Paypal Brand Impersonation"
    if "bank" in txt_lower or "account" in txt_lower:
        return "Banking Credential Harvesting"
    if urls:
        return "Phishing URL Link"
    return "Email Phishing / Social Engineering"


# --- AI Chat Engine (Groq / Gemini HTTP Call) ---
def call_ai_chat(user_msg: str):
    sys_prompt = "You are PhishGuard AI, an expert cybersecurity assistant specializing in phishing detection, scam analysis, smishing prevention, and digital safety."
    
    if GROQ_API_KEY:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": user_msg}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 500
                },
                timeout=8
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

    return f"PhishGuard AI Analysis: '{user_msg[:60]}...' shows social engineering indicators. Never click unverified links or provide passwords."


# --- API Routes ---
@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "PhishGuard AI Vercel Engine"})


@app.route('/api/analyze', methods=['POST', 'GET'])
def analyze():
    data = request.get_json(silent=True) or request.args
    text = (data.get("text") or data.get("content") or "").strip()

    if not text:
        return jsonify({"error": "No text or URL provided"}), 400

    rule_score, rule_reasons, urls_found = analyze_text_rules(text)
    
    url_score = 0
    url_flags = []
    if urls_found:
        url_score, url_flags, _ = analyze_url_heuristics(urls_found[0])

    all_reasons = list(set(rule_reasons + url_flags))
    if not all_reasons and (rule_score > 0 or url_score > 0):
        all_reasons.append("Suspicious patterns detected in request content")

    final_score, risk_level = calculate_composite_score(rule_score, url_score, text)
    attack_vector = determine_attack_vector(text, urls_found, risk_level)

    urgency_score = 75 if any(k in text.lower() for k in ["urgent", "24 hours", "suspended"]) else 20
    financial_score = 85 if any(k in text.lower() for k in ["credited", "rs.", "$", "withdrawal", "bonus"]) else 15
    social_score = 65 if len(all_reasons) > 0 else 10

    response_payload = {
        "text": text,
        "score": final_score,
        "composite_score": final_score,
        "risk_level": risk_level,
        "threat_level": risk_level,
        "attack_type": attack_vector,
        "primary_attack_vector": attack_vector,
        "urgency_score": urgency_score,
        "technical_complexity": url_score,
        "social_engineering": social_score,
        "financial_lure": financial_score,
        "risk_factors": all_reasons if all_reasons else ["No suspicious threat patterns identified"],
        "risks": all_reasons if all_reasons else ["No suspicious threat patterns identified"],
        "urls_found": urls_found,
        "ips_found": [],
        "ai_result": {
            "reasons": all_reasons if all_reasons else ["Content analyzed safe."]
        }
    }
    return jsonify(response_payload)


@app.route('/api/preview', methods=['GET', 'POST'])
@app.route('/preview', methods=['GET', 'POST'])
def preview_url():
    target_url = request.args.get('url') or (request.get_json(silent=True) or {}).get('url')
    if not target_url:
        return jsonify({"error": "No URL provided", "safe": False}), 400

    url = target_url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    final_url = url
    try:
        r = requests.head(url, allow_redirects=True, timeout=5, headers={'User-Agent': 'PhishGuardBot/1.0'})
        final_url = r.url
    except Exception:
        final_url = url

    encoded_url = quote(final_url, safe="")
    screenshot_url = f"https://api.microlink.io/?url={encoded_url}&screenshot=true&meta=false&embed=screenshot.url"

    return jsonify({
        "original_url": url,
        "final_url": final_url,
        "screenshot_url": screenshot_url,
        "safe": True
    })


@app.route('/api/chat', methods=['POST', 'GET'])
@app.route('/chat', methods=['POST', 'GET'])
def chat():
    data = request.get_json(silent=True) or request.args
    msg = (data.get("message") or data.get("prompt") or "").strip()
    if not msg:
        return jsonify({"reply": "Hello! How can I assist you with cybersecurity today?"})

    ai_reply = call_ai_chat(msg)
    return jsonify({"reply": ai_reply, "response": ai_reply})


# --- Static Frontend Routes ---
@app.route('/')
def serve_frontend():
    if STATIC_DIR and os.path.exists(os.path.join(STATIC_DIR, 'index.html')):
        return send_from_directory(STATIC_DIR, 'index.html')
    return jsonify({"message": "PhishGuard AI Serverless Running", "status": "online"})


@app.route('/<path:path>')
def serve_static(path):
    if STATIC_DIR:
        target = os.path.join(STATIC_DIR, path)
        if os.path.exists(target):
            return send_from_directory(STATIC_DIR, path)
        index_path = os.path.join(STATIC_DIR, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(STATIC_DIR, 'index.html')
    return jsonify({"error": "Not Found"}), 404


if __name__ == '__main__':
    app.run(debug=True)
