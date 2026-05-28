from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import email_parser

router = APIRouter()

class HeaderAnalysisRequest(BaseModel):
    raw_headers: str

@router.post("/analyze")
async def analyze_headers(request: HeaderAnalysisRequest):
    if not request.raw_headers or not request.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Headers cannot be empty")
        
    parsed = email_parser.parse_raw_email(request.raw_headers)
    headers = parsed.get("headers", {})
    
    auth_raw = headers.get("authentication_results", "")
    auth = email_parser.parse_auth_header(auth_raw)
    
    # If DKIM-Signature header present but auth header says unknown, mark as present
    if headers.get("dkim_signature") and auth.get("dkim") == "unknown":
        auth["dkim"] = "present_unverified"
        
    return {
        "authentication": auth,
        "sender": {
            "display_name": headers.get("display_name", ""),
            "display_name_spoof": headers.get("display_name_spoof", False),
            "from_email": headers.get("from_email", ""),
            "from_domain": headers.get("from_domain", ""),
            "reply_to": headers.get("reply_to", ""),
            "reply_to_domain": headers.get("reply_to_domain", ""),
            "reply_to_mismatch": headers.get("reply_to_mismatch", False),
        },
        "originating_ip": headers.get("originating_ip"),
        "date": headers.get("date"),
        "subject": headers.get("subject"),
        "message_id": headers.get("message_id"),
        "x_mailer": headers.get("x_mailer"),
    }
