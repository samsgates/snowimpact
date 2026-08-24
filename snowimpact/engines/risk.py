from __future__ import annotations

from collections import defaultdict

from snowimpact.core.models import Decision, Finding, RiskBreakdown, Severity


class RiskEngine:
    WEIGHTS = {
        "security": 0.30,
        "governance": 0.20,
        "dependencies": 0.15,
        "finops": 0.15,
        "performance": 0.10,
        "ai": 0.10,
    }

    def score(self, findings: list[Finding]) -> RiskBreakdown:
        categories: dict[str, list[int]] = defaultdict(list)
        for finding in findings:
            categories[finding.category].append(finding.risk_score)

        values: dict[str, int] = {}
        rationale: list[str] = []
        for category in self.WEIGHTS:
            scores = sorted(categories.get(category, []), reverse=True)
            # Highest finding dominates. Additional findings add diminishing risk.
            value = scores[0] if scores else 0
            if len(scores) > 1:
                value = min(100, value + sum(scores[1:4]) // 10)
            values[category] = value
            if value:
                rationale.append(f"{category}: {value}/100 from {len(scores)} finding(s)")

        overall = round(sum(values[k] * self.WEIGHTS[k] for k in self.WEIGHTS))

        severities = {finding.severity for finding in findings}
        if Severity.CRITICAL in severities and overall < 81:
            overall = 81
            rationale.append("critical finding raises overall risk floor to 81")
        elif Severity.HIGH in severities and overall < 61:
            overall = 61
            rationale.append("high finding raises overall risk floor to 61")
        elif Severity.MEDIUM in severities and overall < 31:
            overall = 31
            rationale.append("medium finding raises overall risk floor to 31")

        # Hard critical conditions cannot be averaged away.
        if any(f.severity == Severity.CRITICAL and f.rule in {"PUBLIC_SENSITIVE_ACCESS", "UNBOUNDED_DML", "ADMIN_ROLE_CHANGE", "AGENT_WRITE_TOOL_EXPOSURE", "MCP_DIRECT_SQL_EXPOSURE"} for f in findings):
            overall = max(overall, 90)
            rationale.append("hard critical finding raises overall risk floor to 90")

        return RiskBreakdown(**values, overall=overall, rationale=rationale)

    @staticmethod
    def default_decision(risk: RiskBreakdown, warn_at: int = 31, approval_at: int = 61, block_at: int = 81) -> Decision:
        if risk.overall >= block_at:
            return Decision.BLOCK
        if risk.overall >= approval_at:
            return Decision.REQUIRE_APPROVAL
        if risk.overall >= warn_at:
            return Decision.WARN
        return Decision.ALLOW
