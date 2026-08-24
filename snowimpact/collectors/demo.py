from __future__ import annotations

from snowimpact.collectors.base import MetadataCollector
from snowimpact.core.models import Capability, EnvironmentSnapshot, GraphEdge, GraphNode


class DemoCollector(MetadataCollector):
    """Deterministic demo topology used for local evaluation and tests."""

    def collect(self, environment: str = "development") -> EnvironmentSnapshot:
        nodes = [
            GraphNode(id="table:PROD.CUSTOMER.CUSTOMERS", node_type="TABLE", fqn="PROD.CUSTOMER.CUSTOMERS"),
            GraphNode(id="column:PROD.CUSTOMER.CUSTOMERS.SSN", node_type="COLUMN", fqn="PROD.CUSTOMER.CUSTOMERS.SSN", attributes={"classification": "PII.CRITICAL", "masked": False}),
            GraphNode(id="column:PROD.CUSTOMER.CUSTOMERS.EMAIL", node_type="COLUMN", fqn="PROD.CUSTOMER.CUSTOMERS.EMAIL", attributes={"classification": "PII", "masked": True}),
            GraphNode(id="column:PROD.CUSTOMER.CUSTOMERS.REGION", node_type="COLUMN", fqn="PROD.CUSTOMER.CUSTOMERS.REGION"),
            GraphNode(id="view:PROD.REPORTING.CUSTOMER_VIEW", node_type="VIEW", fqn="PROD.REPORTING.CUSTOMER_VIEW"),
            GraphNode(id="dbt:marketing.customer_model", node_type="DBT_MODEL", fqn="marketing.customer_model"),
            GraphNode(id="role:ANALYST", node_type="ROLE", fqn="ANALYST"),
            GraphNode(id="role:MARKETING", node_type="ROLE", fqn="MARKETING"),
            GraphNode(id="role:PUBLIC", node_type="ROLE", fqn="PUBLIC"),
            GraphNode(id="user:ALICE", node_type="USER", fqn="ALICE"),
            GraphNode(id="user:BOB", node_type="USER", fqn="BOB"),
            GraphNode(id="warehouse:ANALYTICS_WH", node_type="WAREHOUSE", fqn="ANALYTICS_WH", attributes={"size": "MEDIUM", "auto_suspend": 60}),
            GraphNode(id="query:demo-region-query", node_type="QUERY", fqn="demo-region-query", attributes={"user": "ALICE", "historical": True}),
            GraphNode(id="agent:CUSTOMER_SUPPORT_AGENT", node_type="AGENT", fqn="CUSTOMER_SUPPORT_AGENT", attributes={"role": "ANALYST"}),
            GraphNode(id="mcp:CUSTOMER_MCP", node_type="MCP_SERVER", fqn="CUSTOMER_MCP"),
            GraphNode(id="tool:execute_sql", node_type="MCP_TOOL", fqn="CUSTOMER_MCP.execute_sql", attributes={"write": True, "ddl": True}),
        ]
        edges = [
            GraphEdge(source="column:PROD.CUSTOMER.CUSTOMERS.REGION", target="view:PROD.REPORTING.CUSTOMER_VIEW", edge_type="DEPENDS_ON"),
            GraphEdge(source="column:PROD.CUSTOMER.CUSTOMERS.REGION", target="query:demo-region-query", edge_type="CONSUMED_BY", source_type="ACCESS_HISTORY", confidence=0.95),
            GraphEdge(source="view:PROD.REPORTING.CUSTOMER_VIEW", target="dbt:marketing.customer_model", edge_type="DEPENDS_ON"),
            GraphEdge(source="user:ALICE", target="role:ANALYST", edge_type="GRANTED_TO"),
            GraphEdge(source="user:BOB", target="role:MARKETING", edge_type="GRANTED_TO"),
            GraphEdge(source="agent:CUSTOMER_SUPPORT_AGENT", target="mcp:CUSTOMER_MCP", edge_type="USES"),
            GraphEdge(source="mcp:CUSTOMER_MCP", target="tool:execute_sql", edge_type="EXPOSES"),
        ]
        privileges = [
            {"grantee": "ANALYST", "privilege": "SELECT", "object": "PROD.REPORTING.CUSTOMER_VIEW", "object_type": "VIEW"},
            {"grantee": "MARKETING", "privilege": "USAGE", "object": "PROD.CUSTOMER", "object_type": "SCHEMA"},
        ]
        query_metrics = [
            {"object": "PROD.CUSTOMER.CUSTOMERS.REGION", "executions_month": 3100, "avg_duration_ms": 412, "avg_credits": 0.0021},
            {"object": "PROD.REPORTING.CUSTOMER_VIEW", "executions_month": 8500, "avg_duration_ms": 870, "avg_credits": 0.0042},
        ]
        warehouse_metrics = [
            {"warehouse": "ANALYTICS_WH", "size": "MEDIUM", "monthly_credits": 720.0, "idle_percent": 18.0, "active_hours": 360.0}
        ]
        classifications = [
            {"object": "PROD.CUSTOMER.CUSTOMERS.SSN", "classification": "PII.CRITICAL", "masked": False},
            {"object": "PROD.CUSTOMER.CUSTOMERS.EMAIL", "classification": "PII", "masked": True},
        ]
        capabilities = [Capability(name=n, available=True) for n in [
            "OBJECT_DEPENDENCIES", "QUERY_HISTORY", "QUERY_ATTRIBUTION_HISTORY", "ACCESS_HISTORY",
            "TAG_REFERENCES", "POLICY_REFERENCES", "CORTEX_AGENTS", "MCP_SERVERS", "AGENT_IDENTITY",
        ]]
        return EnvironmentSnapshot(
            account="demo-account",
            environment=environment,
            nodes=nodes,
            edges=edges,
            privileges=privileges,
            query_metrics=query_metrics,
            warehouse_metrics=warehouse_metrics,
            classifications=classifications,
            capabilities=capabilities,
        )

    def doctor(self) -> list[dict[str, object]]:
        return [{"name": c.name, "available": c.available, "reason": "demo"} for c in self.collect().capabilities]
