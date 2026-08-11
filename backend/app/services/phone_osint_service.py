import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import number_type as num_type_fn

async def check_phone_osint(text: str):
    results = []
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, "IN"):
            num = match.number
            results.append(await format_number(num))
    except Exception:
        pass
    return results

async def check_phone_osint_detailed(phone_str: str):
    try:
        num = phonenumbers.parse(phone_str, "IN")
        return await format_number(num)
    except Exception as e:
        return {"error": str(e), "is_valid": False}

async def format_number(num):
    c = carrier.name_for_number(num, "en") or "Unknown"
    country = geocoder.description_for_number(num, "en") or "Unknown"
    tzs = timezone.time_zones_for_number(num)
    ntype = num_type_fn(num)
    type_map = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE",
        4: "PREMIUM_RATE", 5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL",
        8: "PAGER", 9: "UAN", 10: "VOICEMAIL", -1: "UNKNOWN"
    }
    line_type = type_map.get(ntype, "UNKNOWN")
    is_voip = line_type == "VOIP" or "voip" in c.lower() or any(x in c.lower() for x in ["google voice", "textnow", "twilio", "bandwidth"])
    return {
        "number": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
        "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country": country,
        "country_code": num.country_code,
        "carrier": c,
        "line_type": line_type,
        "is_voip": is_voip,
        "is_valid": phonenumbers.is_valid_number(num),
        "is_possible": phonenumbers.is_possible_number(num),
        "timezones": list(tzs),
        "risk": 40 if is_voip else (20 if line_type in ["PREMIUM_RATE", "SHARED_COST"] else 0),
        "risk_reasons": ["VoIP number often used for spoofing"] if is_voip else [],
        "caller_id_hint": f"{c} - {country} - {line_type}"
    }
