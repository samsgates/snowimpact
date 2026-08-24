from snowimpact.core.models import Decision, Finding, Severity
from snowimpact.engines.policy import Policy, PolicyEngine


def test_policy_escalation():
    finding = Finding(category="security", rule="TEST", severity=Severity.HIGH, title="x", description="x", risk_score=80)
    engine = PolicyEngine([Policy(name="p", category="security", min_risk_score=70, action=Decision.REQUIRE_APPROVAL)])
    assert engine.evaluate([finding]).decision == Decision.REQUIRE_APPROVAL
