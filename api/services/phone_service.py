"""
Phone OSINT Intelligence Service v3.2 - Vercel Proxy Copy
"""

import json
import os
import re
from typing import Dict, Any

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

CIRCLE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "india_mobile_circles.json")

CIRCLE_DB: Dict[str, Any] = {}
if os.path.exists(CIRCLE_DB_PATH):
    try:
        with open(CIRCLE_DB_PATH, "r", encoding="utf-8") as f:
            CIRCLE_DB = json.load(f)
    except Exception:
        pass


def get_phone_intel(phone_input: str) -> Dict[str, Any]:
    clean_phone = (phone_input or "").strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if not clean_phone:
        return {
            "phone": phone_input,
            "country": "Unknown",
            "country_code": "XX",
            "state": "Unknown",
            "circle": "Unknown",
            "city_approx": "No number provided",
            "lat_lng_approx": "0.0, 0.0",
            "carrier": "Unknown",
            "line_type": "UNKNOWN",
            "timezone": "UTC",
            "validation": "Invalid",
            "digit_length": "0/10",
            "is_mnp_possible": False,
            "approx_note": "No input provided",
            "risk": 0,
            "is_applicable": False
        }

    if not clean_phone.startswith("+"):
        if len(clean_phone) == 10 and clean_phone[0] in "6789":
            clean_phone = "+91" + clean_phone
        else:
            clean_phone = "+" + clean_phone

    try:
        parsed = phonenumbers.parse(clean_phone, "IN")
        is_valid = phonenumbers.is_valid_number(parsed)
        national = str(parsed.national_number)
        prefix4 = national[:4]
        prefix3 = national[:3]

        info = CIRCLE_DB.get(prefix4) or CIRCLE_DB.get(prefix3) or {
            "circle": "Pan-India",
            "state": "India",
            "city_approx": "Pan-India Region",
            "lat_lng": "20.5937, 78.9629",
            "carrier": "Unknown Provider"
        }

        carrier_name = carrier.name_for_number(parsed, "en")
        if not carrier_name or carrier_name.strip() == "":
            carrier_name = info.get("carrier", "Airtel / Jio / Vi")

        country_desc = geocoder.description_for_number(parsed, "en") or "India"
        country_code_str = phonenumbers.region_code_for_number(parsed) or "IN"

        return {
            "phone": clean_phone,
            "country": f"{country_desc} (+{parsed.country_code}) - {info['state']}",
            "country_code": country_code_str,
            "state": info["state"],
            "circle": info["circle"],
            "city_approx": info["city_approx"],
            "lat_lng_approx": info["lat_lng"],
            "carrier": carrier_name,
            "line_type": "MOBILE" if phonenumbers.number_type(parsed) == 1 else "FIXED",
            "timezone": "Asia/Calcutta",
            "validation": "Valid" if is_valid else "Unallocated / Format Issue",
            "digit_length": f"{len(national)}/10",
            "is_mnp_possible": True,
            "approx_note": "Circle-level approx, not exact GPS - based on original allocation, MNP may change carrier",
            "risk": 0 if is_valid else 25,
            "is_applicable": True
        }
    except Exception as e:
        return {
            "phone": clean_phone,
            "country": "Invalid Format",
            "country_code": "XX",
            "state": "Unknown",
            "circle": "Unknown",
            "city_approx": f"Parsing Error: {e}",
            "lat_lng_approx": "0.0, 0.0",
            "carrier": "Unknown Provider",
            "line_type": "UNKNOWN",
            "timezone": "UTC",
            "validation": "Invalid",
            "digit_length": "Invalid",
            "is_mnp_possible": False,
            "approx_note": "Failed to parse phone number",
            "risk": 40,
            "is_applicable": True
        }

def phone_intel(phone: str) -> Dict[str, Any]:
    return get_phone_intel(phone)
