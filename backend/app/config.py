from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Network Security Compliance Auditor"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Security
    SECRET_KEY: str = "change-this-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRATION_DAYS: int = 7

    # Database - Must use asyncpg for async SQLAlchemy
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/compliance_auditor"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # Celery execution queue (STEP 7). Broker defaults to REDIS_URL when
    # CELERY_BROKER_URL is unset. Tests force memory:// via conftest so no
    # broker is required and tasks never auto-run there.
    CELERY_BROKER_URL: str = ""
    CELERY_TASK_ALWAYS_EAGER: bool = False
    EXECUTION_MAX_ATTEMPTS: int = 3
    EXECUTION_RETRY_BACKOFF_SECONDS: int = 30
    EXECUTION_LEASE_MINUTES: int = 15
    EXECUTION_VISIBILITY_TIMEOUT_SECONDS: int = 1800

    # AI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_RETRIES: int = 3
    AI_CACHE_TTL: int = 3600

    # Rate Limiting (generous for development/demo)
    RATE_LIMIT_PER_MINUTE: int = 600
    RATE_LIMIT_PER_HOUR: int = 10000
    RATE_LIMIT_BURST: int = 200

    # File Upload
    # NOTE: .zip is deliberately absent — ZIP archives are not part of
    # the ingestion contract (one Configuration row per uploaded text
    # file; no safe bounded extraction path exists). See the
    # IngestionEngine module docstring (E01 F5/N7 decision).
    MAX_UPLOAD_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: List[str] = [".txt", ".cfg", ".conf"]

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    # Audit
    AUDIT_FRAMEWORK: str = "CIS"
    AUDIT_PLATFORM: str = "auto"

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings"""
    return Settings()


settings = get_settings()
