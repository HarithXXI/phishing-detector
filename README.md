# PhishGuard AI — Phishing Detection Engine

AI-powered phishing detection tool that analyzes emails, messages, and URLs through four independent detection layers.

## Architecture

```
User Input ──► Rule Engine ──────────────────┐
             ► URL Heuristics ───────────────┤
             ► Threat Intel (VT + AbuseIPDB) ┼──► Scoring ──► Risk Report
             ► AI Reasoning (Groq LLM) ──────┘
```

## Tech Stack

| Layer    | Technology                       |
|----------|----------------------------------|
| Backend  | Python 3.11+, FastAPI, httpx     |
| Frontend | Vanilla HTML / CSS / JS          |
| APIs     | Groq, VirusTotal v3, AbuseIPDB v2 |

## Quick Start

### 1. Clone & configure

```bash
cd backend
cp .env.example .env
# Fill in your API keys in .env
```

### 2. Install dependencies

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
```

### 3. Run the backend

```bash
uvicorn app.main:app --reload
```

### 4. Verify

```
GET http://localhost:8000/health
→ {"status": "ok"}
```

### 5. Open the frontend

Open `frontend/index.html` in your browser (or use Live Server).

## Project Structure

```
phishing-detector/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app entry point
│   │   ├── config.py                # Environment & settings
│   │   ├── routes/analyze.py        # POST /api/analyze
│   │   ├── services/rule_engine.py  # Layer 1: Rule-based detection
│   │   ├── services/url_heuristic.py# Layer 2: URL structural analysis
│   │   ├── services/virustotal_service.py  # Layer 3a: VirusTotal
│   │   ├── services/abuseipdb_service.py   # Layer 3b: AbuseIPDB
│   │   ├── services/groq_service.py # Layer 4: AI reasoning
│   │   └── utils/scoring.py         # Composite score aggregation
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── .gitignore
└── README.md
```

## API Endpoints

| Method | Path           | Description                    |
|--------|----------------|--------------------------------|
| GET    | `/health`      | Health check                   |
| POST   | `/api/analyze`  | Run phishing analysis          |

## License

MIT
