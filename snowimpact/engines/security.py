from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from snowimpact.core.models import Change, EnvironmentSnapshot, Evidence, Finding, Remediation, Severity


class RBACGraph:
    def __init__(self, snapshot: EnvironmentSnapshot):
        self.role_members: dict[str, set[str]] = defaultdict(set)
        self.user_roles: dict[str, set[str]] = defaultdict(set)
        self.privileges: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for edge in snapshot.edges:
            if edge.edge_type != "GRANTED_TO":
                continue
            if edge.source.startswith("user:") and edge.target.startswith("role:"):
                self.user_roles[edge.source.split(":", 1)[1]].add(edge.target.split(":", 1)[1])
            elif edge.source.startswith("role:") and edge.target.startswith("role:"):
                # source role inherits target role
                self.role_members[edge.source.split(":", 1)[1]].add(edge.target.split(":", 1)[1])

        for grant in snapshot.privileges:
            grantee = str(grant.get("GRANTEE_NAME") or grant.get("grantee") or "").upper()
            if grantee:
                self.privileges[grantee].append(grant)

    def roles_for_user(self, user: str) -> set[str]:
        initial = {r.upper() for r in self.user_roles.get(user.upper(), set())}
        result = set(initial)
        queue = deque(initial)
        while queue:
            role = queue.popleft()
            for inherited in self.role_members.get(role, set()):
                inherited = inherited.upper()
                if inherited not in result:
                    result.add(inherited)
                    queue.append(inherited)
        return result

    def users_inheriting_role(self, role: str) -> set[str]:
        target = role.upper()
        return {u for u in self.user_roles if target in self.roles_for_user(u)}


class SecurityEngine:
    SENSITIVE = ("PII", "PHI", "PCI", "SECRET", "AUTH", "FINANCIAL")

    def analyze(self, changes: list[Change], snapshot: EnvironmentSnapshot) -> tuple[list[Finding], set[str]]:
        findings: list[Finding] = []
        users: set[str] = set()
        rbac = RBACGraph(snapshot)
        sensitive = {str(c.get("object", "")).upper(): c for c in snapshot.classifications if any(x in str(c.get("classification", "")).upper() for x in self.SENSITIVE)}

        for change in changes:
            if change.operation.value != "grant":
                continue
            role = str(change.attributes.get("role") or "").upper()
            privilege = str(change.attributes.get("privilege") or "").upper()
            scope = str(change.attributes.get("scope") or "ONE").upper()
            object_fqn = change.object.fqn.upper()
            inheritors = rbac.users_inheriting_role(role)
            users.update(inheritors)

            if privilege == "INHERIT_ROLE":
                granted_role = change.object.name.upper()
                target_type = str(change.attributes.get("target_type") or "ROLE").upper()
                if target_type == "USER":
                    users.add(role)
                admin = granted_role in {"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN"}
                role_privs = rbac.privileges.get(granted_role, [])
                privileged_objects = [str(p.get("NAME") or p.get("object") or "") for p in role_privs if str(p.get("PRIVILEGE") or p.get("privilege") or "").upper() in {"OWNERSHIP", "ALL PRIVILEGES", "SELECT", "MODIFY", "CREATE"}]
                sensitive_objects = [obj for obj in privileged_objects for key in sensitive if key == obj.upper() or key.startswith(obj.upper() + ".")]
                severity = Severity.CRITICAL if admin else Severity.HIGH if sensitive_objects or privileged_objects else Severity.MEDIUM
                findings.append(Finding(
                    category="security",
                    rule="ROLE_PRIVILEGE_ESCALATION",
                    severity=severity,
                    title=f"{role} inherits role {granted_role}",
                    description=f"The proposed role hierarchy change extends {target_type.lower()} {role} with privileges from {granted_role}.",
                    affected_objects=[granted_role, *sorted(set(privileged_objects))],
                    evidence=[Evidence(source="rbac_graph", detail=f"Inherited privileged objects: {', '.join(sorted(set(privileged_objects))[:20]) or 'none observed'}")],
                    risk_score=96 if admin else 82 if sensitive_objects else 62 if privileged_objects else 45,
                    confidence=0.95,
                    remediation=Remediation(summary="Review the complete inherited privilege path and prefer a narrower functional role."),
                    source=change.source.model_dump(),
                ))
                continue

            affected_sensitive = []
            if scope in {"ALL", "FUTURE"}:
                prefix = object_fqn + "."
                affected_sensitive = [obj for obj in sensitive if obj == object_fqn or obj.startswith(prefix)]
            elif change.object.object_type in {"TABLE", "VIEW", "SCHEMA", "DATABASE"}:
                prefix = object_fqn + "."
                affected_sensitive = [obj for obj in sensitive if obj == object_fqn or obj.startswith(prefix)]
            elif object_fqn in sensitive:
                affected_sensitive = [object_fqn]

            is_public = role == "PUBLIC"
            broad = scope in {"ALL", "FUTURE"}
            dangerous_priv = privilege in {"OWNERSHIP", "ALL PRIVILEGES", "CREATE", "USAGE", "MODIFY", "MONITOR"}

            if is_public and (affected_sensitive or broad):
                findings.append(Finding(
                    category="security",
                    rule="PUBLIC_SENSITIVE_ACCESS",
                    severity=Severity.CRITICAL,
                    title="Sensitive or broad access granted to PUBLIC",
                    description=f"The proposed grant gives PUBLIC {privilege} on {change.object.fqn}.",
                    affected_objects=[change.object.fqn, *affected_sensitive],
                    evidence=[Evidence(source="proposed_change", detail=change.sql or "grant"), Evidence(source="classification", detail=f"Sensitive matches: {affected_sensitive[:20]}")],
                    risk_score=100,
                    confidence=0.99,
                    remediation=Remediation(summary="Grant access to a dedicated least-privilege role instead of PUBLIC.", suggested_sql=f"REVOKE {privilege} ON {change.object.object_type} {change.object.fqn} FROM ROLE PUBLIC;"),
                    source=change.source.model_dump(),
                ))
                continue

            if affected_sensitive:
                severity = Severity.CRITICAL if dangerous_priv or privilege in {"SELECT", "ALL PRIVILEGES"} else Severity.HIGH
                findings.append(Finding(
                    category="security",
                    rule="SENSITIVE_PRIVILEGE_EXPANSION",
                    severity=severity,
                    title=f"{role} gains access affecting sensitive data",
                    description=f"Grant {privilege} on {change.object.fqn} expands access to {len(affected_sensitive)} sensitive object(s).",
                    affected_objects=[change.object.fqn, *affected_sensitive],
                    evidence=[Evidence(source="classification", detail=", ".join(affected_sensitive[:20])), Evidence(source="rbac_graph", detail=f"Known users inheriting {role}: {', '.join(sorted(inheritors)) or 'none observed'}")],
                    risk_score=min(100, 70 + len(affected_sensitive) * 3),
                    confidence=0.95,
                    remediation=Remediation(summary="Prefer a reporting view or narrower object grant and require masking for sensitive columns."),
                    source=change.source.model_dump(),
                ))
            elif broad or dangerous_priv:
                findings.append(Finding(
                    category="security",
                    rule="BROAD_PRIVILEGE_GRANT",
                    severity=Severity.HIGH,
                    title="Broad privilege grant requires review",
                    description=f"{role} receives {privilege} with scope {scope} on {change.object.fqn}.",
                    affected_objects=[change.object.fqn],
                    evidence=[Evidence(source="proposed_change", detail=change.sql or "grant")],
                    risk_score=72,
                    confidence=0.9,
                    remediation=Remediation(summary="Replace broad/future grants with explicit least-privilege grants where feasible."),
                    source=change.source.model_dump(),
                ))

            if role in {"ACCOUNTADMIN", "SECURITYADMIN"}:
                findings.append(Finding(
                    category="security",
                    rule="ADMIN_ROLE_CHANGE",
                    severity=Severity.CRITICAL,
                    title=f"Change targets privileged role {role}",
                    description="Administrative-role grants require explicit security approval.",
                    affected_objects=[change.object.fqn],
                    evidence=[Evidence(source="proposed_change", detail=change.sql or "grant")],
                    risk_score=95,
                    confidence=1.0,
                    remediation=Remediation(summary="Use a scoped functional role and keep administrative roles out of application paths."),
                    source=change.source.model_dump(),
                ))
        return findings, users
