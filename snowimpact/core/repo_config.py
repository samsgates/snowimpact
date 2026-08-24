from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class AnalysisConfig(BaseModel):
    lineage: bool = True
    security: bool = True
    governance: bool = True
    finops: bool = True
    performance: bool = True
    ai_governance: bool = True


class RiskConfig(BaseModel):
    warn_at: int = Field(default=31, ge=0, le=100)
    approval_at: int = Field(default=61, ge=0, le=100)
    block_at: int = Field(default=81, ge=0, le=100)

    def model_post_init(self, __context) -> None:
        if not self.warn_at <= self.approval_at <= self.block_at:
            raise ValueError("risk thresholds must satisfy warn_at <= approval_at <= block_at")


class CIConfig(BaseModel):
    fail_closed: bool = False
    min_coverage_percent: int = Field(default=70, ge=0, le=100)


class PrivacyConfig(BaseModel):
    store_raw_queries: bool = False


class RepositoryConfig(BaseModel):
    version: int = 1
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    ci: CIConfig = Field(default_factory=CIConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)


DEFAULT_CONFIG = RepositoryConfig()


def load_repository_config(root: str | Path | None = None) -> RepositoryConfig:
    base = Path(root) if root else Path.cwd()
    path = base / ".snowimpact" / "snowimpact.yaml"
    if not path.exists():
        return RepositoryConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return RepositoryConfig.model_validate(raw)
