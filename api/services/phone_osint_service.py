import phonenumbers
import re
from phonenumbers import carrier, geocoder

async def check_phone_osint(text: str):
    results = []
    # Find phone numbers in text
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, "IN"):
            num = match.number
            c = carrier.name_for_number(num, "en") or "Unknown"
            results.append({
                "number": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
                "country": geocoder.description_for_number(num, "en") or "Unknown",
                "carrier": c,
                "is_voip": any(x in c.lower() for x in ["voip", "google voice", "textnow", "twilio", "bandwidth"]),
                "is_valid": phonenumbers.is_valid_number(num),
                "risk": 35 if "voip" in c.lower() else 0
            })
    except Exception:
        pass

    # Also regex for Indian numbers if none detected via library
    if not results:
        indian = re.findall(r'\+91[6-9]\d{9}|[6-9]\d{9}', text)
        for n in indian[:2]:
            results.append({
                "number": n,
                "country": "India",
                "carrier": "Unknown",
                "is_voip": False,
                "is_valid": True,
                "risk": 10
            })
    return results
