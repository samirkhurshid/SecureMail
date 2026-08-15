from functools import lru_cache
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── API Keys — stored in .env ONLY, never exposed to frontend ──
    VIRUSTOTAL_API_KEY: str = Field(default="")
    ABUSEIPDB_API_KEY: str = Field(default="")
    ANTHROPIC_API_KEY: str = Field(default="")   # For AI threat explainer
    GEMINI_API_KEY: str = Field(default="")      # Free tier AI threat explainer

    # ── Encryption Key (Required — no default) ─────────────────────
    SESSION_ENCRYPTION_KEY: str = Field(default="")

    # ── Email Digest (Resend API) ───────────────────────────────────
    RESEND_API_KEY: str = Field(default="")
    DIGEST_FROM_EMAIL: str = Field(default="SecureMail <digest@yourdomain.com>")


    @model_validator(mode="after")
    def validate_encryption_key(self) -> "Settings":
        if not self.SESSION_ENCRYPTION_KEY or not self.SESSION_ENCRYPTION_KEY.strip():
            raise ValueError(
                "SESSION_ENCRYPTION_KEY environment variable is required. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return self

    # ── App Configuration ──────────────────────────────────────────
    APP_ENV: str = Field(default="development")
    LOG_LEVEL: str = Field(default="INFO")
    SCAN_TIMEOUT_SECONDS: int = Field(default=30, ge=1, le=120)
    MAX_ATTACHMENT_SIZE_MB: int = Field(default=32, ge=1, le=256)

    # ── Rate Limits ────────────────────────────────────────────────
    VT_REQUESTS_PER_MINUTE: int = Field(default=4, ge=1)
    ABUSEIPDB_REQUESTS_PER_DAY: int = Field(default=1000, ge=1)

    # ── Risk Thresholds ────────────────────────────────────────────
    VT_MALICIOUS_THRESHOLD: int = Field(default=3, ge=1)
    ABUSEIPDB_CONFIDENCE_THRESHOLD: int = Field(default=25, ge=0, le=100)
    RISK_SCORE_HIGH: int = Field(default=70, ge=1, le=100)
    RISK_SCORE_MEDIUM: int = Field(default=40, ge=1, le=100)

    # ── Forensics ──────────────────────────────────────────────────
    FORENSICS_LOG_DIR: str = Field(default="./forensics_logs")
    FORENSICS_MAX_LOGS: int = Field(default=10000, ge=1)

    # ── Authentication (Firebase) ────────────────────────────────
    FIREBASE_SERVICE_ACCOUNT_PATH: str = Field(default="./firebase-service-account.json")
    FIREBASE_WEB_API_KEY: str = Field(default="")
    FIREBASE_AUTH_DOMAIN: str = Field(default="mail-31dbb.firebaseapp.com")
    FIREBASE_PROJECT_ID: str = Field(default="mail-31dbb")
    FIREBASE_STORAGE_BUCKET: str = Field(default="mail-31dbb.firebasestorage.app")
    FIREBASE_MESSAGING_SENDER_ID: str = Field(default="843370137586")
    FIREBASE_APP_ID: str = Field(default="1:843370137586:web:5e5d0ed4f7196e39480d6b")

    # ── CORS ───────────────────────────────────────────────────────
    CORS_ALLOWED_ORIGINS: str = Field(default="*")

    @property
    def cors_origins(self) -> list[str]:
        raw = self.CORS_ALLOWED_ORIGINS.strip()
        if raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    def mask_key(self, key: str) -> str:
        """Return a masked version — NEVER expose full key through any API endpoint."""
        if not key:
            return None
        if len(key) < 8:
            return "•" * len(key)
        return f"{key[:4]}{'•' * (len(key) - 8)}{key[-4:]}"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
