from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from snowimpact.core.models import Decision, Finding, Severity


_ACTION_ORDER = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.REQUIRE_APPROVAL: 2,
    Decision.BLOCK: 3,
    Decision.UNKNOWN: 4,
}


@dataclass(slots=True)
class Policy:
    name: str
    category: str | None = None
    rules: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    min_risk_score: int = 0
    action: Decision = Decision.WARN
    description: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.category and finding.category.lower() != self.category.lower():
            return False
        if self.rules and finding.rule not in self.rules:
            return False
        if self.severities and finding.severity.value not in {s.lower() for s in self.severities}:
            return False
        return finding.risk_score >= self.min_risk_score


@dataclass(slots=True)
class ExceptionRule:
    policy: str
    object: str | None = None
    reason: str = ""
    owner: str = ""
    expires: date | None = None

    @property
    def active(self) -> bool:
        return self.expires is None or self.expires >= date.today()


@dataclass(slots=True)
class PolicyEvaluation:
    decision: Decision
    matched: list[dict[str, Any]]
    suppressed: list[dict[str, Any]]


class PolicyEngine:
    def __init__(self, policies: list[Policy] | None = None, exceptions: list[ExceptionRule] | None = None):
        self.policies = policies or []
        self.exceptions = exceptions or []

    @classmethod
    def from_directory(cls, directory: str | Path) -> "PolicyEngine":
        policies: list[Policy] = []
        exceptions: list[ExceptionRule] = []
        root = Path(directory)
        if not root.exists():
            return cls()
        for file in sorted(root.glob("*.y*ml")):
            raw = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            for item in raw.get("policies", []):
                policies.append(Policy(
                    name=item["name"],
                    category=item.get("category"),
                    rules=list(item.get("rules", [])),
                    severities=list(item.get("severities", [])),
                    min_risk_score=int(item.get("min_risk_score", 0)),
                    action=Decision(item.get("action", "warn")),
                    description=item.get("description", ""),
                ))
            for item in raw.get("exceptions", []):
                expiry = item.get("expires")
                if isinstance(expiry, str):
                    expiry = datetime.strptime(expiry, "%Y-%m-%d").date()
                exceptions.append(ExceptionRule(
                    policy=item["policy"], object=item.get("object"), reason=item.get("reason", ""), owner=item.get("owner", ""), expires=expiry
                ))
        return cls(policies=policies, exceptions=exceptions)

    @classmethod
    def from_directories(cls, directories: list[str | Path]) -> "PolicyEngine":
        policies: list[Policy] = []
        exceptions: list[ExceptionRule] = []
        for directory in directories:
            loaded = cls.from_directory(directory)
            policies.extend(loaded.policies)
            exceptions.extend(loaded.exceptions)
        # Last policy with the same name wins, allowing repository policy overrides.
        deduped: dict[str, Policy] = {p.name: p for p in policies}
        return cls(list(deduped.values()), exceptions)

    def _suppressed(self, policy: Policy, finding: Finding) -> ExceptionRule | None:
        for exc in self.exceptions:
            if exc.policy != policy.name or not exc.active:
                continue
            if exc.object and exc.object.upper() not in {o.upper() for o in finding.affected_objects}:
                continue
            return exc
        return None

    def evaluate(self, findings: list[Finding]) -> PolicyEvaluation:
        decision = Decision.ALLOW
        matched: list[dict[str, Any]] = []
        suppressed: list[dict[str, Any]] = []

        # Hard safety override remains deterministic even when no user policy exists.
        for finding in findings:
            if finding.rule in {"PUBLIC_SENSITIVE_ACCESS", "UNBOUNDED_DML"} and finding.severity == Severity.CRITICAL:
                decision = Decision.BLOCK
                matched.append({"policy": "snowimpact-hard-safety", "finding": finding.id, "action": "block"})

        for policy in self.policies:
            for finding in findings:
                if not policy.matches(finding):
                    continue
                exc = self._suppressed(policy, finding)
                if exc:
                    suppressed.append({"policy": policy.name, "finding": finding.id, "reason": exc.reason, "owner": exc.owner, "expires": exc.expires.isoformat() if exc.expires else None})
                    continue
                matched.append({"policy": policy.name, "finding": finding.id, "action": policy.action.value})
                if _ACTION_ORDER[policy.action] > _ACTION_ORDER[decision]:
                    decision = policy.action
        return PolicyEvaluation(decision=decision, matched=matched, suppressed=suppressed)
