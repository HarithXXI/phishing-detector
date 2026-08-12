"""
Scoring module compatibility wrapper for v3.2
"""

from app.utils.final_scoring import calculate_final_score

def calculate_composite_score(*args, **kwargs):
    # Extract kwargs or construct fallbacks
    extracted = kwargs.get("extracted", {"has_obfuscation": False})
    dns = kwargs.get("dns_res") or kwargs.get("dns_result") or {}
    ip = kwargs.get("ip_res") or kwargs.get("ip_result") or {}
    whois = kwargs.get("whois_res") or kwargs.get("whois_result") or {}
    vt = kwargs.get("vt_res") or kwargs.get("vt_result") or {}
    abuse = kwargs.get("abuse_res") or kwargs.get("abuse_result") or {}
    ai = kwargs.get("ai_res") or kwargs.get("ai_result") or {}

    res = calculate_final_score(extracted, dns, ip, whois, vt, abuse, ai)
    # Ensure legacy keys for UI compatibility
    res["breakdown"]["rule"] = res["breakdown"]["ai"]
    res["breakdown"]["url"] = res["breakdown"]["obfuscation"]
    res["breakdown"]["harvester"] = 0
    res["breakdown"]["wfuzz"] = 0
    return res
