from snowimpact.collectors.demo import DemoCollector
from snowimpact.core.models import AnalysisRequest
from snowimpact.engines.analyzer import Analyzer


def test_lineage_and_finops_findings():
    sql = """
    ALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION;
    ALTER WAREHOUSE ANALYTICS_WH SET WAREHOUSE_SIZE='2XLARGE';
    """
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql=sql))
    rules = {f.rule for f in result.findings}
    assert "DOWNSTREAM_BLAST_RADIUS" in rules
    assert "WAREHOUSE_COST_INCREASE" in rules
    assert result.risk.overall > 0


def test_public_sensitive_grant_blocks():
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql="GRANT SELECT ON TABLE PROD.CUSTOMER.CUSTOMERS TO ROLE PUBLIC"))
    rules = {f.rule for f in result.findings}
    assert "PUBLIC_SENSITIVE_ACCESS" in rules
    assert result.decision.value == "block"
    assert result.risk.overall >= 90


def test_unbounded_delete_blocks():
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql="DELETE FROM PROD.CUSTOMER.CUSTOMERS"))
    assert any(f.rule == "UNBOUNDED_DML" for f in result.findings)
    assert result.decision.value == "block"


def test_admin_role_escalation_blocks_by_risk():
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql="GRANT ROLE ACCOUNTADMIN TO ROLE ANALYST"))
    assert any(f.rule == "ROLE_PRIVILEGE_ESCALATION" for f in result.findings)
    assert result.decision.value == "block"


def test_writable_mcp_sql_is_critical():
    sql = '''CREATE MCP SERVER PROD.AI.MCP1 FROM SPECIFICATION $$
tools:
  - name: sql_exec
    type: SYSTEM_EXECUTE_SQL
    title: SQL
    description: execute
    config:
      read_only: false
$$'''
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql=sql))
    assert any(f.rule == "MCP_DIRECT_SQL_EXPOSURE" and f.severity.value == "critical" for f in result.findings)
    assert result.decision.value == "block"


def test_view_projection_avoids_unselected_sensitive_column():
    sql = "CREATE VIEW PROD.REPORTING.SAFE_V AS SELECT EMAIL, REGION FROM PROD.CUSTOMER.CUSTOMERS"
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql=sql))
    assert not any(f.rule == "UNMASKED_SENSITIVE_PROPAGATION" for f in result.findings)
