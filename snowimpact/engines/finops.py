from __future__ import annotations

from snowimpact.core.models import Change, EnvironmentSnapshot, Evidence, Finding, Remediation, Severity


WAREHOUSE_MULTIPLIERS = {
    "XSMALL": 1,
    "X-SMALL": 1,
    "SMALL": 2,
    "MEDIUM": 4,
    "LARGE": 8,
    "XLARGE": 16,
    "X-LARGE": 16,
    "2XLARGE": 32,
    "2X-LARGE": 32,
    "3XLARGE": 64,
    "3X-LARGE": 64,
    "4XLARGE": 128,
    "4X-LARGE": 128,
    "5XLARGE": 256,
    "5X-LARGE": 256,
    "6XLARGE": 512,
    "6X-LARGE": 512,
}


class FinOpsEngine:
    def analyze(self, changes: list[Change], snapshot: EnvironmentSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        wh_metrics = {str(w.get("warehouse") or w.get("WAREHOUSE_NAME") or "").upper(): w for w in snapshot.warehouse_metrics}
        wh_nodes = {n.fqn.upper(): n for n in snapshot.nodes if n.node_type.upper() == "WAREHOUSE"}

        for change in changes:
            if change.object.object_type != "WAREHOUSE" or change.operation.value != "alter":
                continue
            new_size = str(change.attributes.get("warehouse_size") or "").upper()
            if not new_size:
                continue
            wh = change.object.name.upper()
            metric = wh_metrics.get(wh, {})
            node = wh_nodes.get(wh)
            old_size = str((node.attributes.get("size") if node else None) or metric.get("size") or "").upper()
            if old_size not in WAREHOUSE_MULTIPLIERS or new_size not in WAREHOUSE_MULTIPLIERS:
                continue
            old_factor = WAREHOUSE_MULTIPLIERS[old_size]
            new_factor = WAREHOUSE_MULTIPLIERS[new_size]
            ratio = new_factor / old_factor
            current_credits = float(metric.get("monthly_credits") or metric.get("COMPUTE_CREDITS") or 0.0)
            projected = current_credits * ratio
            delta = projected - current_credits
            percent = round((ratio - 1) * 100, 1)
            if ratio <= 1.25:
                continue
            severity = Severity.CRITICAL if ratio >= 4 else Severity.HIGH if ratio >= 2 else Severity.MEDIUM
            findings.append(Finding(
                category="finops",
                rule="WAREHOUSE_COST_INCREASE",
                severity=severity,
                title=f"Warehouse resize may increase compute by {percent:.0f}%",
                description=f"{wh} changes from {old_size} to {new_size}. Historical credits imply approximately {delta:.1f} additional credits per comparable month if utilization remains similar.",
                affected_objects=[wh],
                evidence=[Evidence(source="warehouse_metering", detail=f"Historical monthly credits={current_credits:.1f}; size multiplier {old_factor}->{new_factor}")],
                risk_score=min(100, int(45 + max(0, percent) / 3)),
                confidence=0.72 if current_credits else 0.45,
                remediation=Remediation(summary="Validate workload needs, concurrency, auto-suspend, and query optimization before increasing warehouse size."),
                source={**change.source.model_dump(), "estimated_monthly_credit_delta": round(delta, 3)},
            ))
        return findings
