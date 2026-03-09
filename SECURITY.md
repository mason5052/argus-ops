# Security Policy

## Supported Versions

Security fixes are applied to the latest release only.

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4.0 | No        |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Please report security issues by emailing:

`ehehwnwjs5052@gmail.com`

Include the following in your report:
- description of the vulnerability
- steps to reproduce
- affected version or commit
- potential impact assessment

## Public Repository Data Classification

The public repository must not contain:
- internal IP addresses
- enterprise hostnames
- enterprise node labels
- kubeconfig files
- cloud account credentials
- registry credentials
- private overlay manifests
- production values files
- real API keys or access tokens

Examples in this repository must stay generic and safe to publish.

## Repository Guardrails

Required ignore patterns for local and generated sensitive files:
- `*.pem`
- `*.key`
- `*.crt`
- `*.p12`
- `.env.*`
- `config.yaml`
- `history.db`
- `inventory.db`
- `users.db`
- `sessions.db`
- `audit*.jsonl`
- `*.kubeconfig`
- `*credentials*`

Never commit real secrets, private certificates, kubeconfig files, or enterprise deployment overlays.

## Application Security Notes

All authenticated `/api/*` routes require authentication.
`POST /api/auth/login` and `POST /api/auth/logout` are the only public auth endpoints.
`/healthz` stays public for probes.
`/docs` and `/openapi.json` are admin-only.

Other current safeguards:
- API keys are read from environment variables, never committed into the repository
- the `config show` command masks secret values before display
- audit logs exclude secret payloads, passwords, and raw kubeconfig content
- K8s event sanitization redacts bearer tokens, API keys, and RFC-1918 addresses before AI submission
- AI responses are schema-validated before use
- request timeouts and circuit breakers reduce exposure to runaway retries

## CI And Release Security Model

GitHub Actions in this public repository are limited to PR validation and manual workflow dispatch.
The repository does not automatically publish Docker images, PyPI packages, Helm charts, or GitHub Releases.
Enterprise deployment must be performed manually from a trusted workstation and must use assets stored in a private repository.

## Known Limitations

- kubeconfig files with `exec`-based auth plugins execute local binaries. Only use trusted kubeconfig sources.
- local manual release steps still require maintainer discipline. The public repository cannot enforce private workstation hygiene by itself.
- if an internal identifier was previously committed, Git history cleanup may still be required even after the working tree is fixed.
