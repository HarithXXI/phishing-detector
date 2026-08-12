from fastapi import APIRouter
from pydantic import BaseModel
from app.services.phone_service import phone_intel

router = APIRouter(tags=["Phone OSINT"])

class PhoneRequest(BaseModel):
    phone: str

@router.post("/phone-intel")
@router.post("/api/phone-intel")
async def get_phone_intel(payload: PhoneRequest):
    """
    Single Phone OSINT Analysis Endpoint
    """
    result = phone_intel(payload.phone)
    return result

@router.post("/phone-bulk")
@router.post("/api/phone-bulk")
async def get_phone_bulk(payload: dict):
    """
    Bulk Phone OSINT Analysis Endpoint
    """
    text = payload.get("text", "")
    import re
    numbers = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", text)
    results = [phone_intel(num) for num in numbers]
    return {"phones": results, "count": len(results)}
