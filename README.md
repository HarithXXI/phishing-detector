# PhishGuard AI v3.1 - OSINT & Multi-Layer Threat Detection Engine 🛡️

![PhishGuard AI Banner](https://img.shields.io/badge/PhishGuard_AI-v3.1_OSINT-cyan?style=for-the-badge&logo=shield)
![Python FastAPI](https://img.shields.io/badge/Backend-FastAPI_0.110-009688?style=for-the-badge&logo=fastapi)
![React Vite](https://img.shields.io/badge/Frontend-React_18_Vite_6-61DAFB?style=for-the-badge&logo=react)
![Deployment](https://img.shields.io/badge/Deploy-Vercel_%2B_Render-000000?style=for-the-badge&logo=vercel)

PhishGuard AI v3.1 is an enterprise-grade, multi-layer phishing threat detection and open-source intelligence (OSINT) analysis platform. It combines static rule engines, URL entropy analysis, threat intelligence APIs, domain infrastructure checkers, and LLM reasoning to evaluate links, text, emails, and phone numbers in real time.

---

## 🚀 Key Features & 10 Detection Layers

1. **Regex & Signature Rule Engine**: Evaluates high-risk phishing keywords, urgent call-to-action phrases, and banking scam patterns.
2. **URL Heuristics & Shannon Entropy**: Detects typosquatting, suspicious TLDs, IP-in-URL, path complexity, and obfuscated redirects.
3. **VirusTotal Threat Intel**: Live global malware and malicious domain scanner integration.
4. **AbuseIPDB Reputation**: Live IP abuse confidence and hosting reputation checker.
5. **Groq / Gemini AI Multimodal Reasoning**: AI-driven context verification and threat intent classification.
6. **DNS Security & Infrastructure Checker**: Complete A, MX, SPF, DMARC, and DKIM record validator without false-positive flags.
7. **IP Detail & Hosting Finder**: Identifies geolocation (`city, country`), ISP/ASN, hosting provider IPs vs residential IPs, and proxy/VPN nodes.
8. **Phone OSINT Engine (Caller-ID + numint)**: Hybrid offline Indian series database (`+91` circle & operator resolution) + optional live APIs (`Numverify`, `AbstractAPI`, `IPQS`).
9. **Subdomain Harvester (`crt.sh`)**: Passive SSL certificate transparency subdomain enumeration.
10. **Wfuzz Phishing Kit Path Scanner**: Automated detection of common phishing kit drop locations (`/login.php`, `/.well-known/`, etc.).

---

## 🎨 Unified Smart Input Box

Single unified input field with instant input type auto-detection:
- **Phone Numbers** (`10–15 digits`): Triggers `📱 Phone` OSINT analysis via `POST /api/phone-intel`.
- **URLs / Scam Texts / Emails**: Triggers `🛡️ Threat` multi-layer analysis via `POST /api/analyze`.

---

## 🏗️ Project Architecture & Folder Structure

```text
phishing-detector/
├── api/
│   ├── index.py                  # Vercel proxy & lightweight API entry point
│   ├── services/                 # OSINT services (DNS, IP, Phone, Harvester, Wfuzz)
│   └── utils/                    # Composite scoring engine
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI application entry point
│   │   ├── config.py             # System settings & CORS configuration
│   │   ├── routes/               # API endpoints (/api/analyze, /api/phone-intel, etc.)
│   │   ├── services/             # Core detection services
│   │   └── utils/scoring.py      # Proportional 100% exact-sum composite scoring engine
│   ├── requirements.txt          # Python dependencies (dnspython, phonenumbers, fastapi)
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # React main component with auto-detection box
│   │   ├── components/           # UI components (ResultCard, PhoneResultCard, etc.)
│   │   └── utils/detectType.js   # Instant regex & input length type detector
│   ├── package.json
│   └── vite.config.js
├── vercel.json                   # Vercel deployment configuration
├── render.yaml                   # Render deployment configuration
└── README.md
```

---

## 🛠️ Local Development & Testing

### 1. Backend Setup
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation will be available at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend development server will start at: [http://localhost:5173/](http://localhost:5173/)

---

## 🌐 Dual Deployment Configuration

### Vercel (Frontend + Proxy)
- **`vercel.json`** routes `/api/*` to `api/index.py` (which proxies requests to the Render backend).
- Build command: `cd frontend && npm install && npm run build`
- Output directory: `frontend/dist`

### Render (Backend)
- **`render.yaml`** deploys the FastAPI backend container automatically on Render.
- Build command: `pip install -r backend/requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port 10000`

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for details.
