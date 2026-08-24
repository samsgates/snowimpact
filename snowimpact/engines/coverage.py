from __future__ import annotations

from snowimpact.core.models import Change, Evidence, Finding, Remediation, Severity


class CoverageEngine:
    """Fails safely when a parsed statement is outside SnowImpact's supported change model."""

    def analyze(self, changes: list[Change]) -> list[Finding]:
        findings: list[Finding] = []
        for change in changes:
            if change.operation.value != "unknown":
                continue
            findings.append(Finding(
                category="governance",
                rule="UNSUPPORTED_CHANGE",
                severity=Severity.HIGH,
                title="Statement is not covered by the current change model",
                description="SnowImpact parsed the SQL but cannot reliably simulate its Snowflake impact. Manual review is required.",
                affected_objects=[change.object.fqn],
                evidence=[Evidence(source="sql_parser", detail=change.sql or "")],
                risk_score=78,
                confidence=1.0,
                remediation=Remediation(summary="Use a supported change form or require an explicit platform/security approval before deployment."),
                source=change.source.model_dump(),
            ))
        return findings
