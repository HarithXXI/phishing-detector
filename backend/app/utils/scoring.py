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

    rule_raw: int = len(rule_risks_list) * 20
    url_raw: int = len(url_risks_list) * 20

    vt_val = vt_dict.get('malicious', 0) if isinstance(vt_dict, dict) else 0
    vt_raw: int = int(vt_val or 0) * 10

    abuse_val = abuse_dict.get('risk_score', 0) or abuse_dict.get('abuseConfidenceScore', 0) if isinstance(abuse_dict, dict) else 0
    abuse_raw: int = int(abuse_val or 0) // 2

    ai_raw: int = 25 if (isinstance(ai_dict, dict) and ai_dict.get('is_phishing')) else 0

    whois_val = (whois_dict.get('risk_score') or whois_dict.get('score') or 0) if isinstance(whois_dict, dict) else 0
    whois_raw: int = int(whois_val or 0)

    dns_val = dns_dict.get('risk', 0) if isinstance(dns_dict, dict) else 0
    dns_raw: int = int(dns_val or 0)

    ip_val = ip_dict.get('risk', 0) if isinstance(ip_dict, dict) else 0
    ip_raw: int = int(ip_val or 0)

    harvest_val = harvest_dict.get('risk', 0) if isinstance(harvest_dict, dict) else 0
    harvest_raw: int = int(harvest_val or 0)

    wfuzz_val = wfuzz_dict.get('risk', 0) if isinstance(wfuzz_dict, dict) else 0
    wfuzz_raw: int = int(wfuzz_val or 0)

    raw_breakdown: Dict[str, int] = {
        "rule": rule_raw,
        "url": url_raw,
        "vt": vt_raw,
        "abuse": abuse_raw,
        "ai": ai_raw,
        "whois": whois_raw,
        "dns": dns_raw,
        "ip": ip_raw,
        "harvester": harvest_raw,
        "wfuzz": wfuzz_raw
    }

    raw_sum: int = sum(raw_breakdown.values())

    if raw_sum == 0:
        total = 0
        final_breakdown: Dict[str, int] = {k: 0 for k in raw_breakdown}
    elif raw_sum <= 100:
        total = raw_sum
        final_breakdown = dict(raw_breakdown)
    else:
        total = 100
        scaled: Dict[str, int] = {k: round((v / raw_sum) * 100) for k, v in raw_breakdown.items()}
        diff = 100 - sum(scaled.values())
        if diff != 0:
            max_key = max(list(scaled.keys()), key=lambda k: scaled[k])
            scaled[max_key] += diff
        final_breakdown = scaled

    final_breakdown["total"] = total

    if url_raw > 0:
        vector = "Malicious URL"
    elif rule_raw > 15:
        vector = "Phishing Keywords"
    elif dns_raw >= 20:
        vector = "Suspicious Domain Infrastructure"
    elif ip_raw > 10:
        vector = "Hosting/Proxy Abuse"
    else:
        vector = "Suspicious Content"

    risk_level = "CRITICAL" if total >= 75 else "HIGH" if total >= 50 else "MEDIUM" if total >= 25 else "LOW"

    return {
        "score": total,
        "risk_level": risk_level,
        "vector": vector,
        "attack_type": vector.lower().replace(" ", "_"),
        "breakdown": final_breakdown
    }
