"""
DNS Checker Service wrapper for v3.2
"""

from app.services.dns_service import enrich_dns

async def check_dns_security(domain: str):
    return await enrich_dns(domain)

async def check_dns(domain: str):
    return await enrich_dns(domain)
