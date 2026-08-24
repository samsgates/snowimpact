from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SNOWIMPACT_",
        extra="ignore",
        case_sensitive=False,
    )

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./snowimpact.db"
    redis_url: str = "redis://localhost:6379/0"
    api_key: SecretStr = SecretStr("change-me-in-production")
    demo_mode: bool = True
    log_level: str = "INFO"
    cors_origins: str = ""
    history_days: int = Field(default=90, ge=1, le=365)
    raw_sql_retention_days: int = Field(default=30, ge=0, le=3650)
    telemetry: bool = False
    max_concurrent_metadata_queries: int = Field(default=5, ge=1, le=50)
    analysis_timeout_seconds: int = Field(default=120, ge=10, le=3600)
    max_access_history_rows: int = Field(default=50000, ge=100, le=500000)

    snowflake_account: str | None = Field(default=None, validation_alias="SNOWFLAKE_ACCOUNT")
    snowflake_user: str | None = Field(default=None, validation_alias="SNOWFLAKE_USER")
    snowflake_role: str = Field(default="SNOWIMPACT_MONITOR", validation_alias="SNOWFLAKE_ROLE")
    snowflake_warehouse: str = Field(default="SNOWIMPACT_WH", validation_alias="SNOWFLAKE_WAREHOUSE")
    snowflake_database: str | None = Field(default=None, validation_alias="SNOWFLAKE_DATABASE")
    snowflake_private_key_path: Path | None = Field(default=None, validation_alias="SNOWFLAKE_PRIVATE_KEY_PATH")
    snowflake_private_key_passphrase: SecretStr | None = Field(default=None, validation_alias="SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")

    github_app_id: str | None = Field(default=None, validation_alias="GITHUB_APP_ID")
    github_private_key: SecretStr | None = Field(default=None, validation_alias="GITHUB_PRIVATE_KEY")
    github_webhook_secret: SecretStr | None = Field(default=None, validation_alias="GITHUB_WEBHOOK_SECRET")

    ai_enabled: bool = Field(default=False, validation_alias="AI_ENABLED")
    ai_provider: str | None = Field(default=None, validation_alias="AI_PROVIDER")
    openai_api_key: SecretStr | None = Field(default=None, validation_alias="OPENAI_API_KEY")

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def validate_production_safety(self) -> list[str]:
        problems: list[str] = []
        if self.is_production and self.api_key.get_secret_value() == "change-me-in-production":
            problems.append("SNOWIMPACT_API_KEY must be changed in production")
        if self.is_production and self.demo_mode:
            problems.append("SNOWIMPACT_DEMO_MODE must be false in production")
        return problems


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
