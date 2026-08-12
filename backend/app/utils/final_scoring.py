"""
Final Composite Scoring Engine v3.2 - AI-Driven, Generic Architecture

Total score = ai.risk_score (0-40) + dns.risk (0-40) + ip.risk (0-25) + whois.risk (0-20) + vt.risk (0-40) + abuse.risk (0-35)
Score capped at 100%. No hardcoded brand/shortener rule additions.
"""

from typing import Dict, Any, Optional


def calculate_final_score(
    extracted: Dict[str, Any],
    dns_res: Dict[str, Any],
    ip_res: Dict[str, Any],
    whois_res: Dict[str, Any],
    vt_res: Dict[str, Any],
    abuse_res: Dict[str, Any],
    ai_res: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Computes final risk score, risk level, attack vector, and detailed breakdown.
    """
    ai_score = min(40, max(0, int(ai_res.get("risk_score", 0))))
    dns_score = min(40, max(0, int(dns_res.get("risk", 0))))
    ip_score = min(25, max(0, int(ip_res.get("risk", 0))))
    whois_val = whois_res.get("score", whois_res.get("risk", 0))
    if isinstance(whois_val, str):
        whois_map = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 10, "LOW": 0}
        whois_score = whois_map.get(whois_val.upper(), 0)
    else:
        try:
            whois_score = min(20, max(0, int(whois_val or 0)))
        except (ValueError, TypeError):
            whois_score = 0
    
    # VirusTotal: 8 pts per malicious hit
    vt_malicious = vt_res.get("malicious", 0) if isinstance(vt_res, dict) else 0
    vt_score = min(40, vt_malicious * 8)
    
    # AbuseIPDB: confidence * 0.35
    raw_abuse_conf = 0
    if isinstance(abuse_res, dict):
        raw_abuse_conf = abuse_res.get("confidence") or abuse_res.get("risk_score") or abuse_res.get("abuseConfidenceScore") or 0
    try:
        abuse_conf_val = float(raw_abuse_conf)
    except (ValueError, TypeError):
        abuse_conf_val = 0.0
    abuse_score = min(35, int(abuse_conf_val * 0.35))

    # Obfuscation indicator boost from extractor if URL is heavily obfuscated
    obfuscation_boost = 10 if extracted.get("has_obfuscation") and ai_score > 0 else 0

    raw_total = ai_score + dns_score + ip_score + whois_score + vt_score + abuse_score + obfuscation_boost
    score = min(100, max(0, raw_total))

    # Risk level classification
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Attack vector classification (AI-driven, fallback to score)
    ai_vector = ai_res.get("attack_vector", "")
    ai_confidence = ai_res.get("confidence", 0)

    if score < 20 and not ai_res.get("is_phishing"):
        vector = "Legitimate"
    elif ai_confidence >= 60 and ai_vector and ai_vector != "Legitimate":
        vector = ai_vector
    elif dns_score >= 30:
        vector = "Fake Unresolvable Domain"
    elif ip_score >= 20:
        vector = "Proxy / Suspicious IP Node"
    elif vt_score >= 20:
        vector = "Blacklisted Threat Intel URL"
    else:
        vector = "Suspicious Pattern" if score >= 30 else "Legitimate"

    return {
        "score": score,
        "risk_score": score,
        "level": level,
        "risk_level": level,
        "vector": vector,
        "attack_vector": vector,
        "dns_status": dns_res.get("status", "Unknown"),
        "breakdown": {
            "ai": ai_score,
            "dns": dns_score,
            "ip": ip_score,
            "whois": whois_score,
            "vt": vt_score,
            "abuse": abuse_score,
            "obfuscation": obfuscation_boost,
            "total": score,
        }
    }
