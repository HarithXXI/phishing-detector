from fastapi import APIRouter
from pydantic import BaseModel
from app.services.phone_osint_service import check_phone_osint_detailed

router = APIRouter()

class PhoneRequest(BaseModel):
    phone: str

@router.post("/api/phone-intel")
async def phone_intel(payload: PhoneRequest):
    # Detailed lookup for single number
    result = await check_phone_osint_detailed(payload.phone)
    return result

@router.post("/api/phone-bulk")
async def phone_bulk(payload: dict):
    # Extract all numbers from text like main box
    from app.services.phone_osint_service import check_phone_osint
    text = payload.get("text", "")
    results = await check_phone_osint(text)
    return {"phones": results, "count": len(results)}
