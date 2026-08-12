"""
Phone OSINT Intelligence Service v3.2 - Generic Approximate Intel
"""

import json
import os
import re
from typing import Dict, Any

import phonenumbers
from phonenumbers import geocoder, carrier, timezone

CIRCLE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "india_mobile_circles.json")

CIRCLE_DB: Dict[str, Any] = {}
if os.path.exists(CIRCLE_DB_PATH):
    try:
        with open(CIRCLE_DB_PATH, "r", encoding="utf-8") as f:
            CIRCLE_DB = json.load(f)
    except Exception as e:
        pass


def phone_intel(phone_input: str) -> Dict[str, Any]:
    clean_phone = (phone_input or "").strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if not clean_phone:
        return {
            "phone": phone_input,
            "valid": False,
            "country": "Unknown",
            "region": "Unknown",
            "state": "Unknown",
            "city_approx": "No phone number provided",
            "carrier": "Unknown",
            "line_type": "UNKNOWN",
            "timezone": "UTC",
            "digit_length": "0 digits",
            "lat_lng_approx": "0.0, 0.0",
            "circle": "Unknown",
            "risk": 0,
            "is_applicable": False
        }

    if not clean_phone.startswith("+"):
        if len(clean_phone) == 10 and clean_phone[0] in "6789":
            clean_phone = "+91" + clean_phone
        else:
            clean_phone = "+" + clean_phone

    try:
        parsed = phonenumbers.parse(clean_phone, None)
        is_valid = phonenumbers.is_valid_number(parsed)
        country_code = parsed.country_code
        national_num = str(parsed.national_number)
        region_code = phonenumbers.region_code_for_number(parsed) or "GLOBAL"

        country_name = geocoder.description_for_number(parsed, "en")
        if not country_name:
            if country_code == 91:
                country_name = "India"
            else:
                country_name = f"Country (+{country_code})"

        carrier_name = carrier.name_for_number(parsed, "en") or "Mobile Network Provider"
        tz_list = timezone.time_zones_for_number(parsed)
        tz_str = tz_list[0] if tz_list else ("Asia/Calcutta" if country_code == 91 else "UTC")

        num_type = phonenumbers.number_type(parsed)
        type_str = "MOBILE" if num_type == 1 else ("FIXED_LINE" if num_type == 0 else "VOIP/SPECIAL")

        circle_info = {}
        if country_code == 91:
            prefix4 = national_num[:4]
            prefix3 = national_num[:3]
            circle_info = CIRCLE_DB.get(prefix4) or CIRCLE_DB.get(prefix3) or {}

        circle_name = circle_info.get("circle", "Pan-India Circle" if country_code == 91 else f"{region_code} Circle")
        state_name = circle_info.get("state", "India" if country_code == 91 else country_name)
        city_approx = circle_info.get("city_approx", f"{country_name} - {carrier_name} Circle")
        lat_lng_approx = circle_info.get("lat_lng", "22.57, 88.36" if country_code == 91 else "28.61, 77.20")
        if circle_info.get("carrier") and carrier_name == "Mobile Network Provider":
            carrier_name = circle_info["carrier"]

        digit_count = len(national_num)
        digit_length_str = f"{digit_count}/10 digits" if country_code == 91 else f"{digit_count} digits"

        return {
            "phone": clean_phone,
            "valid": is_valid,
            "country": f"{country_name} (+{country_code})",
            "region": f"{region_code} - {circle_name}",
            "state": state_name,
            "city_approx": city_approx,
            "carrier": carrier_name,
            "line_type": type_str,
            "timezone": tz_str,
            "digit_length": digit_length_str,
            "lat_lng_approx": lat_lng_approx,
            "circle": circle_name,
            "risk": 0 if is_valid else 25,
            "is_applicable": True
        }
    except Exception as e:
        return {
            "phone": clean_phone,
            "valid": False,
            "country": "Invalid Format",
            "region": "Unknown",
            "state": "Unknown",
            "city_approx": f"Parsing error: {e}",
            "carrier": "Unknown Provider",
            "line_type": "UNKNOWN",
            "timezone": "UTC",
            "digit_length": "Invalid",
            "lat_lng_approx": "0.0, 0.0",
            "circle": "Unknown",
            "risk": 40,
            "is_applicable": True
        }
