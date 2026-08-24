from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from snowimpact.collectors.base import MetadataCollector
from snowimpact.core.models import AnalysisRequest, AnalysisResult, AnalysisStatus, Decision
from snowimpact.core.repo_config import RepositoryConfig, load_repository_config
from snowimpact.engines.ai_governance import AIGovernanceEngine
from snowimpact.engines.finops import FinOpsEngine
from snowimpact.engines.coverage import CoverageEngine
from snowimpact.engines.governance import GovernanceEngine
from snowimpact.engines.graph import ImpactGraph
from snowimpact.engines.lineage import LineageEngine
from snowimpact.engines.parser import SnowflakeSQLParser
from snowimpact.engines.performance import PerformanceEngine
from snowimpact.engines.policy import PolicyEngine
from snowimpact.engines.risk import RiskEngine
from snowimpact.engines.security import SecurityEngine


class Analyzer:
    def __init__(self, collector: MetadataCollector, policy_directory: str | Path | None = None, repository_config: RepositoryConfig | None = None):
        self.collector = collector
        self.config = repository_config or load_repository_config()
        self.parser = SnowflakeSQLParser()
        self.lineage = LineageEngine()
        self.security = SecurityEngine()
        self.governance = GovernanceEngine()
        self.finops = FinOpsEngine()
        self.coverage = CoverageEngine()
        self.performance = PerformanceEngine()
        self.ai = AIGovernanceEngine()
        self.risk = RiskEngine()
        built_in = Path(__file__).resolve().parents[1] / "policies"
        if policy_directory:
            self.policy_directories = [built_in, Path(policy_directory)]
        else:
            self.policy_directories = [built_in]
            repo_policies = Path.cwd() / ".snowimpact" / "policies"
            if repo_policies.exists():
                self.policy_directories.append(repo_policies)

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        started = datetime.now(UTC)
        if not request.sql:
            raise ValueError("Analysis request requires SQL")
        snapshot = self.collector.collect(request.environment)
        changes = self.parser.parse(request.sql, request.filename or "inline.sql")
        graph = ImpactGraph(snapshot)

        findings = []
        findings.extend(self.coverage.analyze(changes))
        affected: set[str] = set()
        users: set[str] = set()
        if self.config.analysis.lineage:
            lineage_findings, lineage_affected, lineage_users = self.lineage.analyze(changes, graph)
            findings.extend(lineage_findings)
            affected.update(lineage_affected)
            users.update(lineage_users)
        if self.config.analysis.security:
            security_findings, security_users = self.security.analyze(changes, snapshot)
            findings.extend(security_findings)
            users.update(security_users)
        if self.config.analysis.governance:
            findings.extend(self.governance.analyze(changes, snapshot))
        if self.config.analysis.finops:
            findings.extend(self.finops.analyze(changes, snapshot))
        if self.config.analysis.performance:
            findings.extend(self.performance.analyze(changes, snapshot))
        if self.config.analysis.ai_governance:
            findings.extend(self.ai.analyze(changes, snapshot))

        risk = self.risk.score(findings)
        default_decision = self.risk.default_decision(
            risk,
            warn_at=self.config.risk.warn_at,
            approval_at=self.config.risk.approval_at,
            block_at=self.config.risk.block_at,
        )
        policy = PolicyEngine.from_directories(self.policy_directories)
        policy_result = policy.evaluate(findings)
        order = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.REQUIRE_APPROVAL: 2, Decision.BLOCK: 3, Decision.UNKNOWN: 4}
        decision = policy_result.decision if order[policy_result.decision] > order[default_decision] else default_decision

        unavailable = [c.name for c in snapshot.capabilities if not c.available]
        total_caps = len(snapshot.capabilities)
        coverage = round(100 * (total_caps - len(unavailable)) / total_caps) if total_caps else 100
        min_coverage = self.config.ci.min_coverage_percent
        fail_closed = request.fail_closed or self.config.ci.fail_closed
        if unavailable and coverage < min_coverage and fail_closed:
            decision = Decision.BLOCK
        elif unavailable and coverage < min_coverage and decision == Decision.ALLOW:
            decision = Decision.UNKNOWN

        affected.update(o for f in findings for o in f.affected_objects)
        return AnalysisResult(
            status=AnalysisStatus.COMPLETE,
            decision=decision,
            risk=risk,
            changes=changes,
            findings=findings,
            affected_objects=sorted(affected),
            affected_users=sorted(users),
            coverage_percent=coverage,
            missing_capabilities=unavailable,
            started_at=started,
            completed_at=datetime.now(UTC),
            metadata={
                "account": snapshot.account,
                "environment": snapshot.environment,
                "policy_matches": policy_result.matched,
                "policy_suppressions": policy_result.suppressed,
                "snapshot_collected_at": snapshot.collected_at.isoformat(),
                "config": self.config.model_dump(mode="json"),
            },
        )
