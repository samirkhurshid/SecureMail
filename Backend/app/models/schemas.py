from pydantic import BaseModel, field_validator
from typing import Optional

class EmailScanRequest(BaseModel):
    raw_email: Optional[str] = None
    headers_raw: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None

class URLScanRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('URL cannot be empty or whitespace')
        return v.strip()

class IPCheckRequest(BaseModel):
    ip: str

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('IP cannot be empty or whitespace')
        return v.strip()
