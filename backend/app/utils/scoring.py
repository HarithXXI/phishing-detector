"""
Scoring Utility

Aggregates the four detection layers into a final
phishing risk score (0-100) using a deterministic formula.

Formula:
  rule_score  = min(len(rule_risks) * 6, 25)
  url_score   = min(len(url_risks) * 7, 30)
  vt_score    = 35 if malicious > 0 else 15 if suspicious > 0 else 0
  abuse_score = 20 if abuse > 75 else 15 if abuse > 50 else 0
  ai_score    = 30 if ai.is_phishing else 0
  ai_bonus    = 15 if ai.risk_level == "HIGH" else 0
  final       = clamp(sum, 0, 100)
"""


def calculate_composite_score(
    rule_risks: list[str],
    url_risks: list[str],
    vt_result: dict,
    abuse_result: dict,
    ai_result: dict,
) -> dict:
    """
    Calculate the final composite phishing score using balanced layer weights.

    Max breakdown (Total 100 pts):
      Layer 1: Rule engine       = max 25 pts (5 pts per matched rule)
      Layer 2: URL heuristics    = max 25 pts (8 pts per URL indicator)
      Layer 3: Threat Intel      = max 25 pts (VT: 15 pts, AbuseIPDB: 10 pts)
      Layer 4: AI Reasoning      = max 25 pts (20 pts if phishing + 5 bonus if HIGH)
    """
    # Layer 1: Rule engine (max 25 pts)
    rule_score = min(len(rule_risks) * 5, 25)

    # Layer 2: URL heuristics (max 25 pts)
    url_score = min(len(url_risks) * 8, 25)

    # Layer 3a: VirusTotal (max 15 pts)
    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    if malicious > 0:
        vt_score = 15
    elif suspicious > 0:
        vt_score = 8
    else:
        vt_score = 0

    # Layer 3b: AbuseIPDB (max 10 pts)
    abuse_confidence = abuse_result.get("abuseConfidenceScore", 0)
    if abuse_confidence > 75:
        abuse_score = 10
    elif abuse_confidence > 40:
        abuse_score = 6
    else:
        abuse_score = 0

    # Layer 4: AI reasoning (max 25 pts)
    ai_is_phishing = ai_result.get("is_phishing", False)
    ai_risk_level = (ai_result.get("risk_level") or "LOW").upper()

    ai_score = 20 if ai_is_phishing else 0
    ai_bonus = 5 if ai_risk_level == "HIGH" else 0

    # Final score
    raw_total = rule_score + url_score + vt_score + abuse_score + ai_score + ai_bonus
    final_score = max(0, min(raw_total, 100))

    # Map to risk level
    if final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": final_score,
        "risk_level": risk_level,
        "breakdown": {
            "rule_engine": rule_score,
            "url_heuristic": url_score,
            "virustotal": vt_score,
            "abuseipdb": abuse_score,
            "ai_reasoning": ai_score,
            "ai_bonus": ai_bonus,
        },
    }
