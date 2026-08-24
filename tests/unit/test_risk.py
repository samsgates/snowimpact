from snowimpact.core.models import Finding, Severity
from snowimpact.engines.risk import RiskEngine


def test_hard_critical_floor():
    finding = Finding(category="security", rule="PUBLIC_SENSITIVE_ACCESS", severity=Severity.CRITICAL, title="x", description="x", risk_score=100)
    result = RiskEngine().score([finding])
    assert result.overall >= 90
