# Architecture

SnowImpact uses a normalized change IR and environment snapshot so parsers and analyzers are decoupled.

## Request path

1. CLI/API/GitHub submits proposed change.
2. Parser validates Snowflake SQL and creates normalized Change objects.
3. Collector loads current/historical metadata.
4. ImpactGraph creates transitive object relationships.
5. Engines emit common Finding objects with evidence, confidence, remediation and score.
6. Risk engine calculates explainable category and overall risk.
7. Policy engine escalates or suppresses findings according to versioned policy.
8. Result persists and is returned to CI/dashboard.

## Safety boundary

No proposed SQL reaches `cursor.execute`. Collector SQL is maintained in source code and accesses metadata only.

## Scaling

The included API is synchronous for community usability. The Temporal workflow module is the production extension point for durable high-volume jobs. PostgreSQL is authoritative storage. Redis is cache/coordination only.
