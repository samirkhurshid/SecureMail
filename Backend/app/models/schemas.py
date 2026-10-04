from pydantic import BaseModel, Field, field_validator
from typing import Optional

class EmailScanRequest(BaseModel):
    raw_email: Optional[str] = Field(default=None, max_length=500_000)
    headers_raw: Optional[str] = Field(default=None, max_length=500_000)
    sender_email: Optional[str] = Field(default=None, max_length=500)
    subject: Optional[str] = Field(default=None, max_length=2000)
    deep_scan: bool = Field(default=False, description="When True, queries external VirusTotal and AbuseIPDB. When False, uses ultra-fast local heuristics (<200ms).")

    @field_validator('raw_email', 'headers_raw')
    @classmethod
    def validate_email_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 500_000:
            raise ValueError('Email content exceeds maximum allowed size (500,000 characters).')
        return v

class URLScanRequest(BaseModel):
    url: str = Field(..., max_length=2048)

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('URL cannot be empty or whitespace')
        v = v.strip()
        if len(v) > 2048:
            raise ValueError('URL exceeds maximum allowed length of 2048 characters')
        return v

class IPCheckRequest(BaseModel):
    ip: str = Field(..., max_length=100)

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('IP cannot be empty or whitespace')
        return v.strip()


class PreferencesUpdateRequest(BaseModel):
    digest_enabled: bool


class WebhookUpdateRequest(BaseModel):
    webhook_url: Optional[str] = None


