import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import number_type
import re

INDIA_SERIES = {
    "98": {"circle": "Punjab", "operator": "Airtel / Jio"},
    "99": {"circle": "Mumbai", "operator": "Vodafone Idea"},
    "97": {"circle": "Delhi", "operator": "Airtel"},
    "96": {"circle": "Uttar Pradesh", "operator": "Jio"},
    "95": {"circle": "Punjab", "operator": "BSNL"},
    "94": {"circle": "Punjab", "operator": "Airtel"},
}

def get_indian_fallback(national_str):
    if len(national_str) >= 4:
        prefix = national_str[:4]
        if prefix.startswith("9855"):
            return {"circle": "Punjab", "operator": "Airtel / Jio (9855 series)", "state": "Punjab"}
        if prefix.startswith("98"):
            return {"circle": "North India", "operator": "Airtel / Vodafone", "state": "Punjab/Haryana"}
    return None

async def format_number(num, raw_input=""):
    try:
        national_str = str(num.national_number)
        country = geocoder.description_for_number(num, "en") or "India"
        if not country or country == "":
            country = "India" if num.country_code == 91 else "Unknown"

        carr = carrier.name_for_number(num, "en") or ""
        if not carr and num.country_code == 91:
            fb = get_indian_fallback(national_str)
            carr = fb["operator"] if fb else "Unknown Mobile Operator"
            if fb:
                country = fb["circle"]

        tzs = timezone.time_zones_for_number(num)
        ntype = number_type(num)
        type_map = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE", 4: "PREMIUM_RATE", 6: "VOIP"}
        line_type = type_map.get(ntype, "MOBILE" if len(national_str) >= 9 else "UNKNOWN")
        if num.country_code == 91 and len(national_str) >= 7:
            line_type = "MOBILE"

        is_possible = phonenumbers.is_possible_number(num)
        is_valid = phonenumbers.is_valid_number(num)

        validation_msg = (
            "Valid Number"
            if is_valid
            else f"Invalid - {len(national_str)} digits, need 10 for India"
            if num.country_code == 91
            else "Invalid Format"
        )
        if not is_possible and num.country_code == 91 and len(national_str) == 9:
            validation_msg = f"Invalid - 9 digits detected, Indian numbers need 10. Try +91 {national_str}0"

        return {
            "number": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164) if is_possible else raw_input,
            "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL) if is_possible else raw_input,
            "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if is_possible else raw_input,
            "country": country,
            "country_code": num.country_code,
            "carrier": carr or "Unknown",
            "line_type": line_type,
            "is_voip": "voip" in (carr or "").lower(),
            "is_valid": is_valid,
            "is_possible": is_possible,
            "validation_message": validation_msg,
            "timezones": list(tzs) if tzs else ["Asia/Kolkata"],
            "national_format": national_str,
            "length": len(national_str),
            "risk": 0 if is_valid else 15,
        }
    except Exception as e:
        return {"error": str(e), "raw": raw_input}

async def check_phone_osint_detailed(phone_str: str):
    raw = re.sub(r'[^\d+]', '', phone_str)
    if not raw.startswith('+'):
        raw = '+91' + raw if len(raw) == 10 else '+' + raw
    for region in ["IN", "US", None]:
        try:
            num = phonenumbers.parse(phone_str, region)
            result = await format_number(num, phone_str)
            if result.get("country") != "Unknown" or result.get("is_possible"):
                return result
        except Exception:
            continue
    fallback = get_indian_fallback(re.sub(r'\D', '', phone_str)[-10:])
    return {
        "number": phone_str,
        "national": phone_str,
        "country": "India (+91)" if "91" in phone_str else "Unknown (+91)",
        "country_code": 91,
        "carrier": fallback["operator"] if fallback else "Unknown",
        "line_type": "MOBILE",
        "is_valid": False,
        "validation_message": f"Could not parse - {phone_str} has {len(re.sub(r'\D','',phone_str))} digits",
        "timezones": ["Asia/Kolkata"],
        "national_format": re.sub(r'\D', '', phone_str)[-10:],
        "length": len(re.sub(r'\D', '', phone_str)),
        "risk": 20
    }

async def check_phone_osint(text):
    results = []
    for match in phonenumbers.PhoneNumberMatcher(text, "IN"):
        results.append(await format_number(match.number, match.raw_string))
    if not results:
        nums = re.findall(r'\+?91?\s*[6-9]\d{9}|[6-9]\d{9}', text)
        for n in nums[:3]:
            results.append(await check_phone_osint_detailed(n))
    return results
