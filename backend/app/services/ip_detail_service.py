"""
IP Detail Service wrapper for v3.2
"""

from app.services.ip_service import enrich_ip

async def get_ip_details(target: str):
    return await enrich_ip(target)
