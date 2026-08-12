"""
Phone OSINT Service Wrapper for v3.2
"""

from app.services.phone_service import phone_intel

async def analyze_phone_osint(phone: str):
    return phone_intel(phone)

async def check_phone_osint(phone: str):
    return phone_intel(phone)
