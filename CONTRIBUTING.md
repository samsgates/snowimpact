# Contributing

1. Fork the repository and create a focused branch.
2. Add tests for behavior changes.
3. Run `ruff check snowimpact tests` and `pytest`.
4. Keep analysis decisions deterministic. AI may explain findings but must not silently override policy/risk logic.
5. Never introduce execution of untrusted PR SQL.
6. Do not log secrets or raw Snowflake credentials.
7. Submit a pull request with the problem, approach, tests and compatibility impact.

All contributions are accepted under Apache-2.0.
