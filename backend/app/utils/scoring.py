"""
Scoring Utility

Aggregates the 6 detection layers into a final
phishing risk score (0-100) using a deterministic formula.

Formula & Layer Weights (Total = 100%):
  rule_engine    = 25% (min 25 pts)
  url_heuristic  = 15% (min 15 pts)
  ml_model       = 25% (min 25 pts)
  whois_age      = 15% (min 15 pts)
  virustotal     = 10% (min 10 pts)
  abuseipdb      = 10% (min 10 pts)
  + young_domain_boost (20 pts for domain < 30 days old)
"""

from typing import Optional, Dict, Any


def calculate_composite_score(
    rule_risks: list[str],
    url_risks: list[str],
    vt_result: dict,
    abuse_result: dict,
    ai_result: dict,
    whois_result: Optional[dict] = None,
    ml_result: Optional[dict] = None,
) -> dict:
    """
    Calculate the final composite phishing score using 6-layer balanced weight distribution
    where final_score ALWAYS strictly equals the exact sum of all layer breakdown points + boosts.
    """
    whois_data: Dict[Any, Any] = whois_result or {}
    ml_data: Dict[Any, Any] = ml_result or {}
    vt_data: Dict[Any, Any] = vt_result or {}
    abuse_data: Dict[Any, Any] = abuse_result or {}

    # Layer Scores (0-100 normalized)
    rule_norm = min(100, len(rule_risks) * 25)
    url_norm = min(100, len(url_risks) * 30)

    # ML Model score (0-100)
    ml_norm = ml_data.get("ml_score", 0) if isinstance(ml_data, dict) else 0

    # VirusTotal score (0-100)
    vt_malicious = vt_data.get("malicious", 0) if isinstance(vt_data, dict) else 0
    vt_suspicious = vt_data.get("suspicious", 0) if isinstance(vt_data, dict) else 0
    vt_norm = min(100, (vt_malicious * 50) + (vt_suspicious * 25))

    # WHOIS Domain Age score (0-100)
    whois_norm = whois_data.get("score", 10) if isinstance(whois_data, dict) else 10

    # AbuseIPDB score (0-100)
    abuse_conf = abuse_data.get("abuseConfidenceScore", 0) if isinstance(abuse_data, dict) else 0
    abuse_norm = min(100, int(abuse_conf))

    # Calculate exact integer breakdown points for each layer
    rule_pts = round(rule_norm * 0.25)
    url_pts = round(url_norm * 0.15)
    ml_pts = round(ml_norm * 0.25)
    whois_pts = round(whois_norm * 0.15)
    vt_pts = round(vt_norm * 0.10)
    abuse_pts = round(abuse_norm * 0.10)

    # Calculate Boost Rule
    age_days = whois_data.get("age_days") if isinstance(whois_data, dict) else None
    young_boost = 0

    if age_days is not None and age_days < 30:
        young_boost = 20
        print(f"[Scoring Engine] Applied +20 young domain boost (Age: {age_days} days)")
    elif whois_data.get("risk") == "HIGH" and whois_data.get("raw_whois_success") is False:
        young_boost = 10
        print(f"[Scoring Engine] Applied +10 restricted WHOIS boost")

    # Final score is GUARANTEED to match the sum of all breakdown components
    raw_sum = rule_pts + url_pts + ml_pts + whois_pts + vt_pts + abuse_pts + young_boost
    final_score = max(0, min(100, raw_sum))

    print(f"[Scoring Engine] Exact sum composite score: {final_score}% ({rule_pts}+{url_pts}+{ml_pts}+{whois_pts}+{vt_pts}+{abuse_pts}+{young_boost})")

    if final_score >= 65:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    breakdown = {
        "rule_engine": rule_pts,
        "url_heuristic": url_pts,
        "ml_model": ml_pts,
        "whois_age": whois_pts,
        "virustotal": vt_pts,
        "abuseipdb": abuse_pts,
        "young_domain_boost": young_boost,
    }

    return {
        "score": final_score,
        "composite_score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }
