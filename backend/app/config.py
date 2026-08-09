import os
from dotenv import load_dotenv

load_dotenv()

# --- API Keys ---
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

# --- App Settings ---
APP_TITLE: str = "PhishGuard AI"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = "AI-Powered Phishing Detection Engine"

# --- CORS ---
ALLOWED_ORIGINS: list[str] = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "*",  # Remove in production
]
