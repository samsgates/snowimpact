from __future__ import annotations

from snowimpact.core.models import Change, EnvironmentSnapshot, Evidence, Finding, Remediation, Severity


class PerformanceEngine:
    def analyze(self, changes: list[Change], snapshot: EnvironmentSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        # Static guardrails. Runtime regression testing can be layered via sandbox replay.
        for change in changes:
            sql = (change.sql or "").upper()
            if change.operation.value in {"update", "delete"} and " WHERE " not in f" {sql} ":
                findings.append(Finding(
                    category="performance",
                    rule="UNBOUNDED_DML",
                    severity=Severity.CRITICAL,
                    title="Unbounded DML detected",
                    description=f"{change.operation.value.upper()} has no WHERE clause and can scan or modify a full table.",
                    affected_objects=[change.object.fqn],
                    evidence=[Evidence(source="sql_parser", detail=change.sql or "")],
                    risk_score=92,
                    confidence=0.98,
                    remediation=Remediation(summary="Add an explicit bounded predicate or run through an approved bulk-change workflow."),
                    source=change.source.model_dump(),
                ))
            if "SELECT *" in sql and change.operation.value == "create" and "VIEW" in change.object.object_type:
                findings.append(Finding(
                    category="performance",
                    rule="SELECT_STAR_VIEW",
                    severity=Severity.MEDIUM,
                    title="View uses SELECT *",
                    description="SELECT * increases schema-coupling and can unintentionally propagate newly added columns.",
                    affected_objects=[change.object.fqn],
                    evidence=[Evidence(source="sql_parser", detail=change.sql or "")],
                    risk_score=45,
                    confidence=0.95,
                    remediation=Remediation(summary="List approved columns explicitly in the view definition."),
                    source=change.source.model_dump(),
                ))
        return findings
