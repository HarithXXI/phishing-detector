from typing import Optional, Dict, Any, List

def calculate_composite_score(
    rule_risks: Optional[List[Any]] = None,
    url_risks: Optional[List[Any]] = None,
    vt_res: Optional[Dict[Any, Any]] = None,
    abuse_res: Optional[Dict[Any, Any]] = None,
    ai_res: Optional[Dict[Any, Any]] = None,
    whois_res: Optional[Dict[Any, Any]] = None,
    ml_data: Optional[Dict[Any, Any]] = None,
    dns_res: Optional[Dict[Any, Any]] = None,
    ip_res: Optional[Dict[Any, Any]] = None,
    harvest_res: Optional[Dict[Any, Any]] = None,
    wfuzz_res: Optional[Dict[Any, Any]] = None,
    vt_result: Optional[Dict[Any, Any]] = None,
    abuse_result: Optional[Dict[Any, Any]] = None,
    ai_result: Optional[Dict[Any, Any]] = None,
    whois_result: Optional[Dict[Any, Any]] = None,
    ml_result: Optional[Dict[Any, Any]] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    rule_risks_list = rule_risks or []
    url_risks_list = url_risks or []
    vt_dict = vt_res or vt_result or {}
    abuse_dict = abuse_res or abuse_result or {}
    ai_dict = ai_res or ai_result or {}
    whois_dict = whois_res or whois_result or {}
    dns_dict = dns_res or kwargs.get("dns_result") or {}
    ip_dict = ip_res or kwargs.get("ip_result") or {}
    harvest_dict = harvest_res or kwargs.get("harvest_result") or {}
    wfuzz_dict = wfuzz_res or kwargs.get("wfuzz_result") or {}
    ml_dict = ml_data or ml_result or {}

    rule_score = len(rule_risks_list) * 20
    url_score = len(url_risks_list) * 20
    vt_score = vt_dict.get('malicious', 0) * 10
    abuse_score = (abuse_dict.get('risk_score', 0) or abuse_dict.get('abuseConfidenceScore', 0)) // 2
    ai_score = 25 if ai_dict.get('is_phishing') else 0
    whois_score = whois_dict.get('risk_score', whois_dict.get('score', 0)) if isinstance(whois_dict, dict) else 0
    dns_score = dns_dict.get('risk', 0) if isinstance(dns_dict, dict) else 0
    ip_score = ip_dict.get('risk', 0) if isinstance(ip_dict, dict) else 0
    harvest_score = harvest_dict.get('risk', 0) if isinstance(harvest_dict, dict) else 0
    wfuzz_score = wfuzz_dict.get('risk', 0) if isinstance(wfuzz_dict, dict) else 0

    total = min(100, rule_score + url_score + vt_score + abuse_score + ai_score + whois_score + dns_score + ip_score + harvest_score + wfuzz_score)

    if url_score > 0:
        vector = "Malicious URL"
    elif rule_score > 15:
        vector = "Phishing Keywords"
    elif dns_score >= 20:
        vector = "Suspicious Domain Infrastructure"
    elif ip_score > 10:
        vector = "Hosting/Proxy Abuse"
    else:
        vector = "Suspicious Content"

    risk_level = "CRITICAL" if total >= 75 else "HIGH" if total >= 50 else "MEDIUM" if total >= 25 else "LOW"

    return {
        "score": total,
        "risk_level": risk_level,
        "vector": vector,
        "attack_type": vector.lower().replace(" ", "_"),
        "breakdown": {
            "total": total,
            "rule": rule_score,
            "url": url_score,
            "vt": vt_score,
            "abuse": abuse_score,
            "ai": ai_score,
            "whois": whois_score,
            "dns": dns_score,
            "ip": ip_score,
            "harvester": harvest_score,
            "wfuzz": wfuzz_score
        }
    }
