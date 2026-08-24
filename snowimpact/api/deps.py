from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from snowimpact.core.settings import get_settings


def require_api_key(x_snowimpact_key: str | None = Header(default=None)) -> None:
    settings = get_settings()
    expected = settings.api_key.get_secret_value()
    if settings.env == "development" and expected == "change-me-in-production":
        return
    if not x_snowimpact_key or not secrets.compare_digest(x_snowimpact_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
