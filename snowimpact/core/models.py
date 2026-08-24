from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    UNKNOWN = "unknown"


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    COLLECTING = "collecting"
    PARSING = "parsing"
    BUILDING_GRAPH = "building_graph"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ChangeOperation(StrEnum):
    CREATE = "create"
    ALTER = "alter"
    DROP = "drop"
    GRANT = "grant"
    REVOKE = "revoke"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    MERGE = "merge"
    TRUNCATE = "truncate"
    COPY = "copy"
    CALL = "call"
    UNKNOWN = "unknown"


class ObjectRef(BaseModel):
    object_type: str
    database: str | None = None
    schema_name: str | None = Field(default=None, alias="schema")
    name: str
    column: str | None = None

    model_config = {"populate_by_name": True}

    @property
    def fqn(self) -> str:
        parts = [self.database, self.schema_name, self.name, self.column]
        return ".".join(str(p) for p in parts if p)


class SourceLocation(BaseModel):
    file: str | None = None
    line: int | None = None
    statement_index: int | None = None
    commit_sha: str | None = None


class Change(BaseModel):
    id: str = Field(default_factory=lambda: f"chg_{uuid4().hex[:12]}")
    operation: ChangeOperation
    object: ObjectRef
    source: SourceLocation = Field(default_factory=SourceLocation)
    sql: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    node_type: str
    fqn: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    edge_type: str
    source_type: str = "metadata"
    confidence: float = Field(default=1.0, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    source: str
    detail: str
    freshness_seconds: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Remediation(BaseModel):
    summary: str
    suggested_sql: str | None = None
    patch: str | None = None
    safe_to_auto_apply: bool = False


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"fnd_{uuid4().hex[:12]}")
    category: str
    rule: str
    severity: Severity
    title: str
    description: str
    affected_objects: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0, le=1)
    remediation: Remediation | None = None
    source: dict[str, Any] = Field(default_factory=dict)


class Capability(BaseModel):
    name: str
    available: bool
    reason: str | None = None
    freshness_seconds: int | None = None


class EnvironmentSnapshot(BaseModel):
    account: str = "demo"
    environment: str = "development"
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    privileges: list[dict[str, Any]] = Field(default_factory=list)
    query_metrics: list[dict[str, Any]] = Field(default_factory=list)
    warehouse_metrics: list[dict[str, Any]] = Field(default_factory=list)
    classifications: list[dict[str, Any]] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RiskBreakdown(BaseModel):
    security: int = 0
    governance: int = 0
    dependencies: int = 0
    finops: int = 0
    performance: int = 0
    ai: int = 0
    overall: int = 0
    rationale: list[str] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    sql: str | None = None
    filename: str | None = "inline.sql"
    environment: str = "development"
    repository: str | None = None
    commit_sha: str | None = None
    fail_closed: bool = False


class AnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: f"an_{uuid4().hex[:12]}")
    status: AnalysisStatus = AnalysisStatus.COMPLETE
    decision: Decision
    risk: RiskBreakdown
    changes: list[Change]
    findings: list[Finding]
    affected_objects: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    coverage_percent: int = Field(default=100, ge=0, le=100)
    missing_capabilities: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)
