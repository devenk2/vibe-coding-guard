# NIST SSDF — RV: Respond to Vulnerabilities

These rules map to the NIST SSDF "Respond to Vulnerabilities" practice group.

## RV.1 — Identify and Remediate Vulnerabilities
- Never hardcode passwords, API keys, tokens, or other secrets in source code
- Use environment variables (os.environ, process.env) for configuration secrets
- Use dedicated secret management systems for production (AWS Secrets Manager, HashiCorp Vault, etc.)
- Common secret patterns to avoid:
  - AWS keys (AKIA...)
  - GitHub tokens (ghp_...)
  - API keys (sk-...)
  - Slack tokens (xox[bpsa]-...)
  - Private keys (BEGIN PRIVATE KEY)
  - Database URLs with embedded credentials

## RV.2 — Avoid Known-Vulnerable Patterns
- Do not use deprecated or known-insecure APIs
- Keep dependencies updated to patch known CVEs
- Monitor security advisories for your dependencies
- Avoid patterns with known exploit chains (pickle deserialization, prototype pollution)

## RV.3 — Track and Resolve Security Issues
- Address security findings immediately — do not defer
- Security TODOs should be treated as blockers, not backlog items
- Document security decisions and trade-offs
