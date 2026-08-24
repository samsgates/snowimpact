from __future__ import annotations

from snowimpact.core.models import Change, EnvironmentSnapshot, Evidence, Finding, Remediation, Severity


class GovernanceEngine:
    SENSITIVE_MARKERS = ("PII", "PHI", "PCI", "SECRET", "AUTH", "FINANCIAL")

    def analyze(self, changes: list[Change], snapshot: EnvironmentSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        classes = {str(c.get("object", "")).upper(): c for c in snapshot.classifications}

        for change in changes:
            refs = [str(r).upper() for r in change.attributes.get("references", [])]
            projected = {str(c).upper() for c in change.attributes.get("projected_columns", [])}
            if change.operation.value == "create" and "VIEW" in change.object.object_type and refs:
                sensitive_refs = []
                unmasked_refs = []
                for ref in refs:
                    for obj, meta in classes.items():
                        # Table-level references are narrowed to projected columns when known.
                        if obj == ref or obj.startswith(ref + "."):
                            if projected and "*" not in projected and "." in obj and obj.rsplit(".", 1)[-1].upper() not in projected:
                                continue
                            classification = str(meta.get("classification", "")).upper()
                            if any(marker in classification for marker in self.SENSITIVE_MARKERS):
                                sensitive_refs.append(obj)
                                if meta.get("masked") is False:
                                    unmasked_refs.append(obj)
                if unmasked_refs:
                    findings.append(Finding(
                        category="governance",
                        rule="UNMASKED_SENSITIVE_PROPAGATION",
                        severity=Severity.CRITICAL,
                        title="New view may propagate unmasked sensitive data",
                        description=f"{change.object.fqn} references sources with {len(unmasked_refs)} unmasked sensitive columns.",
                        affected_objects=[change.object.fqn, *unmasked_refs],
                        evidence=[Evidence(source="classification", detail=", ".join(unmasked_refs[:20]))],
                        risk_score=min(100, 85 + len(unmasked_refs)),
                        confidence=0.85,
                        remediation=Remediation(summary="Apply a masking policy or expose only approved, de-identified columns before publishing the view."),
                        source=change.source.model_dump(),
                    ))
                elif sensitive_refs:
                    findings.append(Finding(
                        category="governance",
                        rule="SENSITIVE_DATA_PROPAGATION",
                        severity=Severity.MEDIUM,
                        title="New view depends on sensitive data",
                        description="Protection appears present, but downstream governance should be validated.",
                        affected_objects=[change.object.fqn, *sensitive_refs],
                        evidence=[Evidence(source="classification", detail=", ".join(sensitive_refs[:20]))],
                        risk_score=48,
                        confidence=0.8,
                        remediation=Remediation(summary="Verify tag and masking policy propagation in the target environment."),
                        source=change.source.model_dump(),
                    ))
        return findings
