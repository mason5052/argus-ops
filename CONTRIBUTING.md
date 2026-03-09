# Contributing to Argus-Ops

This document describes how to contribute to Argus-Ops in its current v0.4.x development state.

## Development Setup

Requirements:
- Python 3.10 or newer
- access to a Kubernetes cluster only if you are working on live collector behavior
- optional Docker, GitHub token, and AWS profile if you are testing discovery collectors locally

Create a local environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,web,auth]"
```

## Public Repository Boundary

This repository is public.
Do not commit or document any of the following here:
- internal IP addresses
- enterprise hostnames
- enterprise node labels
- production overlays or values files
- kubeconfig files
- registry credentials
- cloud account mappings
- real API keys or tokens

Enterprise deployment overlays and environment-specific values must stay in a private repository.

## Project Focus Areas

The current project is organized around these layers:
- discovery collectors
- analyzer capability contracts
- web and CLI authentication
- audit logging
- dashboard and API
- Kubernetes remediation hooks

Important modules:
- `src/argus_ops/collectors/`
- `src/argus_ops/analyzers/`
- `src/argus_ops/web/`
- `src/argus_ops/auth/`
- `src/argus_ops/audit/`
- `src/argus_ops/inventory_store.py`
- `src/argus_ops/discovery.py`
- `src/argus_ops/engine/pipeline.py`

## Collector Rules

When adding or updating a collector:
- subclass `BaseCollector`
- declare `name`, `infra_type`, and `provided_capabilities`
- keep `collect()` focused on structured runtime snapshots
- use `discover()` for inventory graph output
- avoid aggressive scanning or implicit credential harvesting
- prefer evidence already available on the host or in configured credentials

If a collector adds new fields that analyzers depend on, update the analyzer capability requirements and tests in the same change.

## Analyzer Rules

When adding or updating an analyzer:
- subclass `BaseAnalyzer`
- declare `required_capabilities` when the analyzer needs a specific collector contract
- do not assume a field exists unless the collector contract guarantees it
- prefer skipping unsupported analyzers over returning misleading empty output

## Auth And Audit Rules

Argus-Ops now uses two user roles only:
- `viewer`
- `admin`

Do not reintroduce extra runtime roles without updating:
- `src/argus_ops/auth/models.py`
- `src/argus_ops/web/api.py`
- `src/argus_ops/cli.py`
- `README.md`
- Helm RBAC templates
- related tests

All new authenticated actions should be reflected in audit logging. Do not log secrets, passwords, tokens, or raw kubeconfig content.

## Docs Drift Policy

Documentation must match the running product.

When you change any of the following, update `README.md` in the same branch:
- CLI commands
- collectors
- supported roles
- authenticated API routes
- Helm RBAC profiles
- health probe paths
- MCP manifest behavior
- manual release guidance
- public repository boundary rules

The test suite includes docs drift checks. A feature is not complete if the code changed but the README still describes the old behavior.

## Testing

Run the full validation set before opening a pull request:

```bash
ruff check src/ tests/
pytest
```

Useful focused commands:

```bash
pytest tests/test_api.py -v
pytest tests/test_cli.py -v
pytest tests/test_auth.py -v
pytest tests/test_docs_drift.py -v
helm template argus-ops ./deploy/helm/argus-ops \
  --set image.repository=argus-ops \
  --set image.tag=manual
```

Testing expectations:
- new user-visible behavior requires tests
- API tests should verify both authentication and authorization
- collector changes should include capability or inventory assertions
- README-impacting changes should keep docs drift tests passing
- public examples must remain generic and enterprise-safe

## Manual Release And Deployment

GitHub Actions in this repository run validation only.
Do not add Docker publish, PyPI publish, GitHub Release, or enterprise deployment automation to this public repository.

Manual release work belongs on a trusted maintainer workstation and should remain outside GitHub-hosted automation.
If you need environment-specific Helm values or Kubernetes manifests, store them in a private repository.

## Security Review Checklist

Before opening a pull request, verify all of the following:
- no internal IP addresses
- no enterprise hostnames
- no real node labels tied to a company environment
- no credentials in examples
- no kubeconfig or cert/key material
- no automatic release or deployment workflow additions
- README and SECURITY docs still match the code and `.gitignore`

## Helm And Container Changes

If you touch deployment behavior, verify at least these assumptions:
- `/healthz` stays public for probes
- `/docs` stays admin-only
- config is mounted separately from writable runtime state
- `rbac.profile=viewer` remains read-only
- `rbac.profile=admin` is the only profile that grants mutating Kubernetes verbs
- public-safe defaults remain generic and do not expose enterprise topology

## Pull Requests

Before opening a pull request:
1. keep changes scoped to one coherent concern
2. update tests
3. update README when product behavior changed
4. update SECURITY or CONTRIBUTING when repository boundary rules changed
5. mention known limitations explicitly instead of implying unfinished features are complete

## Security

Security-sensitive areas include:
- auth token handling
- password hashing
- audit record content
- AI prompt sanitization
- Kubernetes write actions
- RBAC templates
- manual release documentation
- public repository safety rules

Treat any change in those areas as high-risk and include regression coverage.

