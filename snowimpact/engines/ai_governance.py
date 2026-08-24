from __future__ import annotations

from snowimpact.core.models import Change, EnvironmentSnapshot, Evidence, Finding, Remediation, Severity


class AIGovernanceEngine:
    def analyze(self, changes: list[Change], snapshot: EnvironmentSnapshot) -> list[Finding]:
        findings: list[Finding] = []

        for change in changes:
            object_type = change.object.object_type.upper()
            if object_type == "MCP SERVER" and change.operation.value == "create":
                tools = change.attributes.get("mcp_tools", [])
                if not isinstance(tools, list):
                    tools = []
                for tool in tools:
                    if not isinstance(tool, dict):
                        continue
                    tool_type = str(tool.get("type") or "").upper()
                    if tool_type == "SYSTEM_EXECUTE_SQL":
                        read_only = tool.get("read_only", True) is not False
                        severity = Severity.HIGH if read_only else Severity.CRITICAL
                        findings.append(Finding(
                            category="ai",
                            rule="MCP_DIRECT_SQL_EXPOSURE",
                            severity=severity,
                            title="MCP server exposes direct SQL execution",
                            description=(
                                "SYSTEM_EXECUTE_SQL allows MCP clients to issue SQL directly. "
                                + ("The tool is read-only, but it can bypass governed semantic/agent paths." if read_only else "read_only is disabled, so write operations can be submitted through the MCP surface.")
                            ),
                            affected_objects=[change.object.fqn, str(tool.get("name") or "SYSTEM_EXECUTE_SQL")],
                            evidence=[Evidence(source="mcp_specification", detail=f"tool={tool.get('name')} type=SYSTEM_EXECUTE_SQL read_only={read_only}")],
                            risk_score=82 if read_only else 98,
                            confidence=0.99,
                            remediation=Remediation(summary="Prefer exposing a governed Cortex Agent. If direct SQL is required, isolate it in a dedicated MCP server and keep read_only=true with a least-privileged role."),
                            source=change.source.model_dump(),
                        ))
                    elif tool_type == "GENERIC" and str(tool.get("config_type") or "").lower() == "procedure":
                        findings.append(Finding(
                            category="ai",
                            rule="MCP_PROCEDURE_TOOL",
                            severity=Severity.HIGH,
                            title="MCP server exposes a stored procedure tool",
                            description="A GENERIC procedure can perform side effects depending on its implementation and execution role.",
                            affected_objects=[change.object.fqn, str(tool.get("identifier") or tool.get("name") or "procedure")],
                            evidence=[Evidence(source="mcp_specification", detail=f"identifier={tool.get('identifier')} warehouse={tool.get('warehouse')}")],
                            risk_score=76,
                            confidence=0.9,
                            remediation=Remediation(summary="Review procedure side effects, caller/owner rights, input validation, warehouse access, and require approval for mutating actions."),
                            source=change.source.model_dump(),
                        ))

            if object_type == "AGENT" and change.operation.value == "create":
                tools = change.attributes.get("agent_tools", [])
                if isinstance(tools, list) and len(tools) > 12:
                    findings.append(Finding(
                        category="ai",
                        rule="AGENT_TOOL_SURFACE_EXPANSION",
                        severity=Severity.MEDIUM,
                        title="Agent exposes a large tool surface",
                        description=f"The proposed agent declares {len(tools)} tools. Larger tool surfaces increase privilege and orchestration complexity.",
                        affected_objects=[change.object.fqn],
                        evidence=[Evidence(source="agent_specification", detail=", ".join(str(t.get("name")) for t in tools if isinstance(t, dict)))],
                        risk_score=52,
                        confidence=0.85,
                        remediation=Remediation(summary="Split responsibilities across narrower agents or remove tools that are not required for the agent's purpose."),
                        source=change.source.model_dump(),
                    ))

        # Existing-state signal from metadata collectors that can enumerate MCP tools.
        dangerous_tools = [n for n in snapshot.nodes if n.node_type.upper() == "MCP_TOOL" and (n.attributes.get("write") or n.attributes.get("ddl"))]
        agents = [n for n in snapshot.nodes if n.node_type.upper() == "AGENT"]
        ai_change = any(c.object.object_type.upper() in {"AGENT", "MCP SERVER", "MCP TOOL"} for c in changes)
        if dangerous_tools and agents and ai_change:
            findings.append(Finding(
                category="ai",
                rule="AGENT_WRITE_TOOL_EXPOSURE",
                severity=Severity.CRITICAL,
                title="Agent environment includes writable or DDL-capable MCP tools",
                description=f"Observed {len(dangerous_tools)} dangerous MCP tool(s) in an environment with {len(agents)} agent(s).",
                affected_objects=[n.fqn for n in [*agents, *dangerous_tools]],
                evidence=[Evidence(source="agent_graph", detail=", ".join(n.fqn for n in dangerous_tools))],
                risk_score=94,
                confidence=0.8,
                remediation=Remediation(summary="Split read/write tools, enforce least privilege, and require human approval for write or DDL actions."),
            ))
        return findings
