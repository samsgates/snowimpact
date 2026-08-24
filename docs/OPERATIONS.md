# Operations

## SLO reference

- API availability: 99.9%
- analysis completion: 99.5%
- webhook ingestion: 99.99%

## Metrics

- `snowimpact_analyses_total{decision=...}`
- `snowimpact_analysis_duration_seconds`

Add infrastructure metrics from Kubernetes/PostgreSQL/Redis and Snowflake query tags in production.

## Backups

Use PostgreSQL point-in-time recovery. Test restores routinely. Policy source should also live in Git.

## Incident behavior

For production CI, choose fail-closed when risk coverage is legally/security critical. Development environments can choose fail-open while clearly exposing UNKNOWN/partial coverage.
