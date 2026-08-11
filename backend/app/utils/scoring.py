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
    rules_list = rule_risks or []
    urls_list = url_risks or []
    vt_dict = vt_res or vt_result or {}
    abuse_dict = abuse_res or abuse_result or {}
    ai_dict = ai_res or ai_result or {}
    whois_dict = whois_res or whois_result or {}
    dns_dict = dns_res or kwargs.get("dns_result") or {}
    ip_dict = ip_res or kwargs.get("ip_result") or {}
    harvest_dict = harvest_res or kwargs.get("harvest_result") or {}
    wfuzz_dict = wfuzz_res or kwargs.get("wfuzz_result") or {}

    # 1. Rule Signatures (0-35) - keywords weight by severity
    rule_score = 0
    for r in rules_list:
        if isinstance(r, dict):
            w = r.get('weight', 10)
            rule_name = str(r.get('rule', '')).lower()
        else:
            w = 10
            rule_name = str(r).lower()
        
        if 'paypal' in rule_name and 'secure' in rule_name:
            w = 25
        if 'account blocked' in rule_name or 'account locked' in rule_name:
            w = 20
        rule_score += w
    rule_score = min(35, rule_score)

    # 2. URL Structure (0-25)
    url_score = min(25, sum(u.get('weight', 10) if isinstance(u, dict) else 10 for u in urls_list))

    # 3. VirusTotal - BOOST from *4 to *8 (1 hit = 8 pts, 5 hits = 40 pts = HIGH)
    vt_mal = vt_dict.get('malicious', 0) if isinstance(vt_dict, dict) else 0
    vt_score = min(40, vt_mal * 8)

    # 4. AbuseIPDB - confidence 0-100 -> 0-35 pts
    abuse_conf = abuse_dict.get('confidence', abuse_dict.get('risk_score', abuse_dict.get('abuseConfidenceScore', 0))) if isinstance(abuse_dict, dict) else 0
    abuse_score = min(35, int(abuse_conf * 0.35))

    # 5. AI Reasoning (0-30) - Groq / Gemini
    ai_score = 30 if (isinstance(ai_dict, dict) and ai_dict.get('is_phishing')) else 0

    # 6. WHOIS Age (0-20) - new domain = high risk
    whois_age = whois_dict.get('age_days', 9999) if isinstance(whois_dict, dict) and whois_dict.get('age_days') is not None else 9999
    if whois_age < 30:
        whois_score = 20
    elif whois_age < 90:
        whois_score = 12
    elif whois_age < 365:
        whois_score = 5
    else:
        whois_score = 0

    # 7. DNS - FIX FALSE POSITIVE
    dns_score = 0
    dns_status = "Valid Domain"
    if isinstance(dns_dict, dict) and dns_dict:
        a_records = dns_dict.get('A') or (dns_dict.get('checks', {}).get('A'))
        mx_records = dns_dict.get('MX') or (dns_dict.get('checks', {}).get('MX'))
        spf_record = dns_dict.get('SPF') or (dns_dict.get('checks', {}).get('SPF'))
        dmarc_record = dns_dict.get('DMARC') or (dns_dict.get('checks', {}).get('DMARC'))

        if a_records is False or (isinstance(a_records, list) and len(a_records) == 0 and dns_dict.get('checks', {}).get('A') is False):
            dns_score = 40
            dns_status = "Domain does not exist - Fake"
        elif not mx_records and not spf_record:
            dns_score = 15
            dns_status = "No mail server - suspicious"
        elif not mx_records:
            dns_score = 3
            dns_status = "No MX but SPF present - OK"
        elif not dmarc_record:
            dns_score = 5
            dns_status = "Missing DMARC"

    # 8. IP Detail - Hosting is NOT malicious, only proxy is
    ip_score = 0
    if isinstance(ip_dict, dict) and ip_dict:
        if ip_dict.get('is_proxy') or ip_dict.get('is_vpn'):
            ip_score = 25
        elif ip_dict.get('is_hosting'):
            ip_score = 5
        if ip_dict.get('abuse_confidence', 0) > 50:
            ip_score += 15

    # 9. Harvester - few subs = new domain = risky
    harvest_score = 0
    if isinstance(harvest_dict, dict) and harvest_dict:
        sub_count = harvest_dict.get('subdomain_count', len(harvest_dict.get('subdomains', [])))
        if sub_count == 0 and ("." in str(kwargs.get("domain", ""))):
            harvest_score = 12
        elif sub_count < 3:
            harvest_score = 5

    # 10. Wfuzz - phishing kit paths
    wfuzz_score = min(25, len(wfuzz_dict.get('exposed_paths', [])) * 8) if isinstance(wfuzz_dict, dict) else 0

    # TOTAL - capped at 100
    total = rule_score + url_score + vt_score + abuse_score + ai_score + whois_score + dns_score + ip_score + harvest_score + wfuzz_score
    score = min(100, total)

    # ATTACK VECTOR - based on highest contributor, not Unknown
    scores_map = {
        "Malicious URL": url_score,
        "Phishing Keywords": rule_score,
        "Blacklisted by VirusTotal": vt_score,
        "Abused IP": abuse_score,
        "AI Detected Phishing": ai_score,
        "New Suspicious Domain": whois_score,
        "Suspicious DNS": dns_score,
        "Proxy/Hosting Abuse": ip_score,
        "No Digital Footprint": harvest_score,
        "Phishing Kit Exposed": wfuzz_score
    }

    max_vector = max(list(scores_map.keys()), key=lambda k: scores_map[k])
    vector = max_vector if score > 10 else "Legitimate"
    if score < 15:
        vector = "Legitimate"

    if score >= 81:
        level = "CRITICAL"
    elif score >= 61:
        level = "HIGH"
    elif score >= 31:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "risk_level": level,
        "vector": vector,
        "attack_type": vector.lower().replace(" ", "_"),
        "dns_status": dns_status,
        "breakdown": {
            "total": score,
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
