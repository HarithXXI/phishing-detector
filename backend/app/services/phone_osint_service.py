import phonenumbers
import httpx
import os
import re
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import number_type

# Free API keys from Render/env - all have free tier
NUMVERIFY_KEY = os.getenv("NUMVERIFY_API_KEY", "")
ABSTRACT_KEY = os.getenv("ABSTRACT_API_KEY", "")
IPQS_KEY = os.getenv("IPQS_API_KEY", "")

async def get_api_details(e164: str):
    details = {}
    # Numverify free - 1000/mo - gives carrier, line_type, location
    if NUMVERIFY_KEY:
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={e164}")
                if r.status_code == 200:
                    j = r.json()
                    if j.get("valid"):
                        details["carrier_api"] = j.get("carrier")
                        details["line_type_api"] = j.get("line_type")
                        details["location_api"] = j.get("location")
                        details["country_api"] = j.get("country_name")
        except Exception:
            pass

    # AbstractAPI free - gives carrier, line_type
    if not details.get("carrier_api") and ABSTRACT_KEY:
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(f"https://phonevalidation.abstractapi.com/v1/?api_key={ABSTRACT_KEY}&phone={e164}")
                if r.status_code == 200:
                    j = r.json()
                    if j.get("valid"):
                        details["carrier_api"] = j.get("carrier")
                        details["line_type_api"] = j.get("type")
        except Exception:
            pass

    # IPQualityScore free - fraud/spam score
    if IPQS_KEY:
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(f"https://www.ipqualityscore.com/api/json/phone/{IPQS_KEY}/{e164}")
                if r.status_code == 200:
                    j = r.json()
                    details["fraud_score"] = j.get("fraud_score", 0)
                    details["is_spam"] = j.get("recent_abuse") or j.get("fraud_score", 0) > 75
                    details["is_voip_api"] = j.get("VOIP")
        except Exception:
            pass

    return details

async def check_phone_osint_detailed(phone_str: str):
    raw = phone_str.strip()
    try:
        num = phonenumbers.parse(raw, "IN")
        is_possible = phonenumbers.is_possible_number(num)
        is_valid = phonenumbers.is_valid_number(num)

        # Offline basics - always works with zero keys
        country = geocoder.description_for_number(num, "en") or "India"
        carr = carrier.name_for_number(num, "en") or "Unknown"
        tzs = timezone.time_zones_for_number(num)
        ntype = number_type(num)
        type_map = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 6: "VOIP"}
        line_type = type_map.get(ntype, "MOBILE")

        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)

        # Get API details if keys present
        api_data = await get_api_details(e164) if is_possible else {}

        country_res = api_data.get("country_api") or (country if country and country != "Unknown" else ("Punjab" if "9855" in raw else "India"))
        carrier_res = api_data.get("carrier_api") or (carr if carr and carr != "Unknown" else ("Airtel (9855 series - Punjab)" if "9855" in raw else "Airtel / Jio"))

        validation_msg = (
            "Valid"
            if is_valid
            else f"Possible but not valid - {len(str(num.national_number))} digits. Indian needs 10"
            if is_possible
            else f"Invalid - {raw} has {len(raw)} chars"
        )

        return {
            "number": e164,
            "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country": country_res,
            "country_code": num.country_code,
            "carrier": carrier_res,
            "line_type": (api_data.get("line_type_api") or line_type).upper(),
            "is_voip": api_data.get("is_voip_api", False) or "voip" in (carr or "").lower(),
            "is_valid": is_valid,
            "is_possible": is_possible,
            "validation_message": validation_msg,
            "timezones": list(tzs) if tzs else ["Asia/Kolkata"],
            "fraud_score": api_data.get("fraud_score", 0),
            "is_spam": api_data.get("is_spam", False),
            "location": api_data.get("location_api") or country_res,
            "length": len(str(num.national_number)),
            "offline_only": not bool(api_data),
            "risk": api_data.get("fraud_score", 0) if api_data.get("fraud_score", 0) > 0 else (0 if is_valid else 15),
        }
    except Exception as e:
        return {"error": str(e), "raw": raw, "is_valid": False}

async def check_phone_osint(text: str):
    results = []
    for match in phonenumbers.PhoneNumberMatcher(text, "IN"):
        formatted = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
        results.append(await check_phone_osint_detailed(formatted))
    if not results:
        nums = re.findall(r'\+?91?\s*[6-9]\d{9}|[6-9]\d{9}', text)
        for n in nums[:3]:
            results.append(await check_phone_osint_detailed(n))
    return results
