from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── API Keys ───────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = Field(default="")
    ABUSEIPDB_API_KEY: str = Field(default="")

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

    # ── CORS ───────────────────────────────────────────────────────
    CORS_ALLOWED_ORIGINS: str = Field(default="*")

    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS_ALLOWED_ORIGINS into a list. Use '*' for all or comma-separated URLs."""
        raw = self.CORS_ALLOWED_ORIGINS.strip()
        if raw == "*":
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
