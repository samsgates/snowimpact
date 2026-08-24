from __future__ import annotations

from snowimpact.core.models import Change, Evidence, Finding, Remediation, Severity
from snowimpact.engines.graph import ImpactGraph


class LineageEngine:
    def analyze(self, changes: list[Change], graph: ImpactGraph) -> tuple[list[Finding], set[str], set[str]]:
        findings: list[Finding] = []
        affected: set[str] = set()
        affected_users: set[str] = set()
        for change in changes:
            if change.operation.value not in {"drop", "alter"}:
                continue
            downstream = graph.downstream(change.object.fqn)
            if not downstream:
                continue
            objects = [str(x["fqn"]) for x in downstream]
            affected.update(objects)
            affected_users.update(str(x["user"]) for x in downstream if x.get("user"))
            max_depth = max(int(x["depth"]) for x in downstream)
            severity = Severity.CRITICAL if change.operation.value == "drop" and len(objects) >= 5 else Severity.HIGH if change.operation.value == "drop" else Severity.MEDIUM
            findings.append(Finding(
                category="dependencies",
                rule="DOWNSTREAM_BLAST_RADIUS",
                severity=severity,
                title=f"{len(objects)} downstream objects may be affected",
                description=f"{change.operation.value.upper()} on {change.object.fqn} reaches {len(objects)} downstream objects across {max_depth} dependency levels.",
                affected_objects=[change.object.fqn, *objects],
                evidence=[Evidence(source="dependency_graph", detail=f"Transitive descendants: {', '.join(objects[:20])}")],
                risk_score=min(100, 35 + len(objects) * 5),
                confidence=0.95,
                remediation=Remediation(summary="Deprecate or stage the change, validate downstream consumers, and update dependent models before deployment."),
                source=change.source.model_dump(),
            ))
        return findings, affected, affected_users
