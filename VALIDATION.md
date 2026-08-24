# SnowImpact validation record

This source archive was release-checked before packaging.

## Completed checks

- Python source tree compiles successfully with `python -m compileall`.
- `pyproject.toml` parses successfully as TOML.
- Deterministic smoke analysis passed using the parser fallback path, including:
  - column drop blast-radius analysis
  - historical-query consumer attribution
  - warehouse resize FinOps analysis
  - sensitive-data grant to `PUBLIC` blocking
  - unbounded DML blocking
  - role privilege-escalation detection
  - writable MCP direct SQL blocking
  - safe view projection without unrelated sensitive-column false positives
  - SQL comments and Snowflake dollar-quoted specification handling
- GitHub webhook HMAC verification logic is covered by tests.
- Source archive is checked with `unzip -t` after creation.

## Environment limitation

The build container used for packaging cannot reach PyPI/npm registries, so a fresh dependency installation and full `pytest`/Next.js build could not be executed inside this packaging environment. CI definitions are included and are intended to run the full dependency-backed Python and web test/build matrix in a network-enabled runner.

## Recommended release gate in your environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,otel]'
pytest
ruff check .

cd web
npm install
npm run lint
npm run build
```

For live Snowflake verification, configure the least-privilege role using `scripts/snowflake_setup.sql`, set `SNOWIMPACT_DEMO_MODE=false`, and run:

```bash
snowimpact doctor
snowimpact scan
```
