from snowimpact.collectors.demo import DemoCollector
from snowimpact.core.models import AnalysisRequest
from snowimpact.engines.analyzer import Analyzer


def test_demo_pipeline_is_explainable():
    result = Analyzer(DemoCollector()).analyze(AnalysisRequest(sql="ALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION"))
    assert result.findings
    assert result.findings[0].evidence
    assert result.coverage_percent == 100
    assert result.metadata["account"] == "demo-account"
    assert "ALICE" in result.affected_users
