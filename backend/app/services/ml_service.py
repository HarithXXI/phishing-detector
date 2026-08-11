"""
Machine Learning Phishing Detection Service for PhishGuard Engine
Loads trained XGBoost model (xgboost_phishing.pkl) and extracts 30-feature vector from URLs/text.
"""

import os
import re
import pickle
import urllib.parse
from typing import Dict, Any, List

# Target model path
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
MODEL_PKL_PATH = os.path.join(MODELS_DIR, "xgboost_phishing.pkl")

# In-memory cache for loaded model metadata
_XGB_MODEL_CACHE: Dict[str, Any] = {}

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "cutt.ly", "goo.gl", "is.gd", "t.co", "ow.ly", "buff.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".site", ".click", ".online", ".work", ".zip", ".icu", ".tk", ".ga", ".cf", ".gq", ".ml"}
URGENT_KEYWORDS = {"login", "verify", "secure", "update", "account", "banking", "signin", "support", "alert", "service"}


def load_xgboost_model() -> Dict[str, Any]:
    """Load trained XGBoost pickle model into memory."""
    global _XGB_MODEL_CACHE
    if _XGB_MODEL_CACHE:
        return _XGB_MODEL_CACHE

    if os.path.exists(MODEL_PKL_PATH):
        try:
            with open(MODEL_PKL_PATH, "rb") as f:
                _XGB_MODEL_CACHE = pickle.load(f)
                print(f"[ML Service] Successfully loaded XGBoost model from {MODEL_PKL_PATH}")
                return _XGB_MODEL_CACHE
        except Exception as e:
            print(f"[ML Service Model Load Error]: {e}")

    return {}


def extract_features_for_ml(url_or_text: str) -> List[int]:
    """
    Map input URL or text to 30 features matching UCI dataset schema:
    [-1, 1, 0 values representing threat presence]
    """
    text = url_or_text.strip() if url_or_text else ""
    parsed = urllib.parse.urlparse(text if text.startswith(("http://", "https://")) else f"https://{text}")
    hostname = (parsed.netloc or parsed.path).split(":")[0].lower()

    # 1. having_IP_Address (-1 if IP present, 1 if domain string)
    ip_match = bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    having_IP_Address = -1 if ip_match else 1

    # 2. URL_Length (-1 if len >= 75, 0 if 54-75, 1 if < 54)
    length = len(text)
    if length >= 75:
        URL_Length = -1
    elif length >= 54:
        URL_Length = 0
    else:
        URL_Length = 1

    # 3. Shortining_Service (-1 if shortener, 1 otherwise)
    is_shortener = any(s in hostname for s in SHORTENER_DOMAINS)
    Shortining_Service = -1 if is_shortener else 1

    # 4. having_At_Symbol (-1 if '@' present, 1 otherwise)
    having_At_Symbol = -1 if "@" in text else 1

    # 5. double_slash_redirecting (-1 if '//' after position 7, 1 otherwise)
    double_slash_pos = text.rfind("//")
    double_slash_redirecting = -1 if double_slash_pos > 7 else 1

    # 6. Prefix_Suffix (-1 if '-' in hostname, 1 otherwise)
    Prefix_Suffix = -1 if "-" in hostname else 1

    # 7. having_Sub_Domain (-1 if subdomains > 2, 0 if == 2, 1 if <= 1)
    parts = hostname.split(".")
    dot_count = len(parts) - 1
    if dot_count > 2:
        having_Sub_Domain = -1
    elif dot_count == 2:
        having_Sub_Domain = 0
    else:
        having_Sub_Domain = 1

    # 8. SSLfinal_State (1 if secure HTTPS, -1 if insecure HTTP)
    is_https = text.lower().startswith("https://")
    SSLfinal_State = 1 if is_https else -1

    # 9. Domain_registeration_length (-1 if suspicious TLD, 1 otherwise)
    tld = f".{parts[-1]}" if len(parts) > 1 else ""
    Domain_registeration_length = -1 if tld in SUSPICIOUS_TLDS else 1

    # 10. Favicon
    Favicon = -1

    # 11. port
    port = 1 if parsed.port and parsed.port not in (80, 443) else -1

    # 12. HTTPS_token
    HTTPS_token = 1 if "https" in hostname else -1

    # 13. Request_URL
    Request_URL = -1

    # 14. URL_of_Anchor
    URL_of_Anchor = 1 if any(kw in text.lower() for kw in URGENT_KEYWORDS) else -1

    # 15. Links_in_tags
    Links_in_tags = -1

    # 16. SFH
    SFH = -1

    # 17. Submitting_to_email
    Submitting_to_email = 1 if "mailto:" in text.lower() else -1

    # 18. Abnormal_URL
    Abnormal_URL = 1 if hostname != "" and not re.match(r"^[a-z0-9\.\-]+$", hostname) else -1

    # 19. Redirect
    Redirect = 1 if "redirect" in text.lower() else -1

    # 20-30 defaults matching feature array length of 30
    on_mouseover = -1
    RightClick = -1
    popUpWidnow = -1
    Iframe = -1
    age_of_domain = 1 if tld in SUSPICIOUS_TLDS else -1
    DNSRecord = -1
    web_traffic = -1
    Page_Rank = -1
    Google_Index = -1
    Links_pointing_to_page = 0
    Statistical_report = 1 if (ip_match or is_shortener) else -1

    feature_vector = [
        having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol,
        double_slash_redirecting, Prefix_Suffix, having_Sub_Domain, SSLfinal_State,
        Domain_registeration_length, Favicon, port, HTTPS_token, Request_URL,
        URL_of_Anchor, Links_in_tags, SFH, Submitting_to_email, Abnormal_URL,
        Redirect, on_mouseover, RightClick, popUpWidnow, Iframe, age_of_domain,
        DNSRecord, web_traffic, Page_Rank, Google_Index, Links_pointing_to_page,
        Statistical_report
    ]

    return feature_vector


def predict_with_xgboost(url_or_text: str) -> Dict[str, Any]:
    """
    Predict phishing risk score (0-100) using trained XGBoost Classifier.
    """
    text = url_or_text.strip() if url_or_text else ""
    features = extract_features_for_ml(text)

    reasons = []
    if features[0] == -1:
        reasons.append("Bare IP address used instead of domain hostname")
    if features[2] == -1:
        reasons.append("URL shortening service detected (URL masking)")
    if features[3] == -1:
        reasons.append("Suspicious '@' symbol in URL")
    if features[5] == -1:
        reasons.append("Hyphenated brand spoofing in domain name")
    if features[6] == -1:
        reasons.append("Multiple subdomains detected")
    if features[7] == -1:
        reasons.append("Insecure HTTP protocol used")
    if features[8] == -1:
        reasons.append("High-risk top-level domain (.xyz, .top, .site, etc.)")
    if features[13] == 1:
        reasons.append("Urgent authentication keyword present")

    model_data = load_xgboost_model()
    if not model_data or "model" not in model_data:
        # Fallback heuristic calculation if model pickle is missing
        fallback_score = 90 if (features[8] == 1 or features[0] == 1 or features[2] == 1) else (60 if features[5] == 1 else 10)
        return {
            "is_phishing": fallback_score >= 40,
            "ml_score": fallback_score,
            "confidence": 0.85,
            "model": "XGBoost Fallback Heuristic",
            "reasons": reasons if reasons else ["Standard structural analysis"]
        }

    try:
        model = model_data["model"]

        # Ensure features array length matches model expectation
        expected_n_features = model.n_features_in_ if hasattr(model, "n_features_in_") else 30
        if len(features) < expected_n_features:
            features.extend([-1] * (expected_n_features - len(features)))
        elif len(features) > expected_n_features:
            features = features[:expected_n_features]

        # Predict probability of class 1 (Phishing)
        import numpy as np
        feats_arr = np.array([features])
        prob_phishing = float(model.predict_proba(feats_arr)[0][1])

        ml_score = round(prob_phishing * 100.0)

        # Boost score if structural threat flags are explicitly triggered
        if len(reasons) >= 3 or (features[7] == -1 and features[8] == -1):
            ml_score = max(ml_score, 85)
        elif len(reasons) >= 2:
            ml_score = max(ml_score, 65)

        confidence = round(0.82 + (abs(prob_phishing - 0.5) * 0.35), 2)

        return {
            "is_phishing": ml_score >= 40,
            "ml_score": ml_score,
            "confidence": confidence,
            "model": "XGBoost Classifier (UCI Trained)",
            "prob_phishing": round(prob_phishing, 3),
            "reasons": reasons if reasons else ["XGBoost model detected legitimate structural patterns"]
        }
    except Exception as e:
        print(f"[XGBoost Prediction Error]: {e}")
        return {
            "is_phishing": False,
            "ml_score": 30,
            "confidence": 0.5,
            "model": "XGBoost Error Fallback",
            "reasons": ["XGBoost prediction encountered exception"]
        }


# Alias for analyze router compatibility
predict_ml = predict_with_xgboost


if __name__ == "__main__":
    print("Testing XGBoost Prediction...")
    res_phish = predict_with_xgboost("http://paypal-login.xyz")
    print("Phishing URL result:", res_phish)

    res_legit = predict_with_xgboost("https://google.com")
    print("Legit URL result:", res_legit)
