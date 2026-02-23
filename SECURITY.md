# Security Policy

## Supported Versions

Security fixes are applied to the latest release only.

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3.0 | No        |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing:

**ehehwnwjs5052@gmail.com**

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce (proof-of-concept code if possible)
- Affected version(s)
- Potential impact assessment

### What to Expect

- **Acknowledgment**: within 2 business days
- **Initial assessment**: within 5 business days
- **Fix timeline**: depends on severity
  - Critical: patch released within 7 days
  - High: patch released within 14 days
  - Medium/Low: addressed in the next scheduled release

You will be credited in the release notes unless you request otherwise.

---

## Security Design Notes

### Data Handling

Argus-Ops collects infrastructure metadata and may send it to external AI providers.
The following safeguards are in place:

**K8s event redaction** (`collectors/k8s.py`):
- Bearer tokens and API keys are stripped from event messages before AI submission
- Private registry credentials embedded in image pull error messages are removed
- Internal RFC-1918 IP addresses are replaced with `[INTERNAL-IP]`
- Event messages are truncated to 512 characters

**LLM response validation** (`ai/provider.py`):
- AI responses are size-limited to 32 KB before parsing
- Responses are validated against a Pydantic schema (`_DiagnosisResponse`)
- Markdown code fences are stripped via regex before JSON parsing

**Cost protection** (`ai/cost.py`):
- Per-run cost limits enforced using `decimal.Decimal` (no float rounding drift)
- AI calls are skipped when the budget limit is reached

**Configuration**:
- API keys are read from environment variables, never stored in config files
- The `config show` command masks secret values before display

### Network

- All K8s API calls use a 30-second timeout (`_API_TIMEOUT`)
- All LLM completion calls use a 60-second timeout (`_LLM_TIMEOUT`)
- Circuit breaker prevents runaway retry storms against unavailable collectors

### Credentials

- Never commit API keys, kubeconfig files, or `.env` files to the repository
- The `.gitignore` excludes `*.pem`, `*.key`, `.env`, `config.yaml`, `history.db`

---

## Known Limitations

- Argus-Ops does not authenticate the `/api/*` endpoints when running `argus-ops serve`.
  The server binds to `127.0.0.1` by default. If you expose it on `0.0.0.0`, add a
  reverse proxy with authentication in front of it.
- kubeconfig files with `exec`-based auth plugins execute local binaries. Ensure your
  kubeconfig comes from a trusted source.
