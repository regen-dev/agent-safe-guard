# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in agent-safe-guard, please report it responsibly.

**Email:** Open a private security advisory on GitHub via the [Security tab](https://github.com/regen-dev/agent-safe-guard/security/advisories/new).

Please include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

The following are in scope:

- Bypass of hook enforcement (tool calls executing without policy evaluation)
- Daemon socket permission issues allowing unauthorized access
- Rule engine regex denial-of-service (catastrophic backtracking)
- Catalog package integrity bypass (SHA256 check circumvention)
- Information disclosure through audit logs or state files

The following are out of scope:

- Issues in Claude Code itself (report to Anthropic)
- Issues in bats-core test framework (report upstream)
- Social engineering or phishing

## Supported Versions

| Version | Supported |
|---------|-----------|
| main branch (source install) | Yes |
| Older commits | Best effort |

## Disclosure Policy

We follow coordinated disclosure. Please allow up to 90 days for a fix before public disclosure.
