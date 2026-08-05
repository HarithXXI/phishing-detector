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

    Score Breakdown:
      Layer 1: Rule Engine       = max 35 pts
      Layer 2: URL Heuristics    = max 45 pts
      Layer 3: Threat Intel      = max 35 pts (VT + AbuseIPDB)
      Layer 4: AI Reasoning      = max 25 pts
    """
    rule_score = min(len(rule_risks) * 12, 60)
    url_score = min(len(url_risks) * 15, 80)

    # Layer 3a: VirusTotal
    vt_malicious = vt_result.get("malicious", 0) if isinstance(vt_result, dict) else 0
    vt_suspicious = vt_result.get("suspicious", 0) if isinstance(vt_result, dict) else 0
    vt_score = min(80, (vt_malicious * 40) + (vt_suspicious * 20))

    # Layer 3b: AbuseIPDB
    abuse_conf = abuse_result.get("abuseConfidenceScore", 0) if isinstance(abuse_result, dict) else 0
    abuse_score = min(80, int(abuse_conf * 0.8))

    raw_score = max(
        rule_score + int(url_score * 0.6),
        url_score + int(rule_score * 0.6),
        vt_score,
        abuse_score,
    )

    if (rule_score > 0 or url_score > 0) and (vt_score > 0 or abuse_score > 0):
        raw_score += 20
    elif rule_score >= 25 and url_score >= 25:
        raw_score += 15

    final_score = max(0, min(raw_score, 100))

    if final_score >= 65:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    breakdown = {
        "rule_engine": min(rule_score, 35),
        "url_heuristic": min(url_score, 45),
        "virustotal": min(vt_score, 35),
        "abuseipdb": min(abuse_score, 20),
        "ai_reasoning": 20 if final_score >= 30 else 0,
        "ai_bonus": 5 if final_score >= 65 else 0,
    }

    return {
        "score": final_score,
        "composite_score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }
