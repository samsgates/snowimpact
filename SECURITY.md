# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability involving credentials, authentication bypass, remote code execution, tenant isolation, webhook verification, or Snowflake privilege escalation.

Report privately to the project security contact configured by the repository owner. Include affected version, reproduction steps, expected/actual behavior, and impact. Avoid including real customer data or credentials.

## Supported versions

Security fixes are provided for the latest stable minor release. Enterprise deployments should pin container/package versions and apply security updates through a controlled change process.

## Security boundaries

- PR SQL is untrusted input and must only be parsed.
- Snowflake metadata access must use least privilege.
- Secrets must come from a secret manager/environment, not source control.
- AI integrations are optional and disabled by default.
