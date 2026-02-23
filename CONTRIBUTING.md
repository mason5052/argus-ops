# Contributing to Argus-Ops

Thank you for considering a contribution to Argus-Ops. This guide covers everything
you need to get started, from setting up a development environment to submitting a
pull request.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment](#development-environment)
4. [Project Structure](#project-structure)
5. [Making Changes](#making-changes)
6. [Testing](#testing)
7. [Code Style](#code-style)
8. [Submitting a Pull Request](#submitting-a-pull-request)
9. [Reporting Bugs](#reporting-bugs)
10. [Requesting Features](#requesting-features)
11. [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful and constructive in all interactions.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/argus-ops.git
   cd argus-ops
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/mason5052/argus-ops.git
   ```

---

## Development Environment

Python 3.10 or higher is required.

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# Install in editable mode with all dev dependencies
pip install -e ".[dev,web]"

# Verify installation
argus-ops --version
```

---

## Project Structure

```
argus-ops/
  src/argus_ops/
    collectors/         Infrastructure data collectors (K8s, SSH, Prometheus)
      base.py           BaseCollector ABC -- implement this to add a new collector
      k8s.py            Kubernetes collector
    analyzers/          Rule-based analyzers that produce Findings
      base.py           BaseAnalyzer ABC -- implement this to add a new analyzer
      pod_health.py     Pod crash/pending/restart detection
      node_health.py    Node NotReady/pressure detection
      resource.py       Missing resource limits detection
    ai/
      base.py           BaseAIProvider ABC
      provider.py       LiteLLM-based AI provider
      cost.py           Token/cost tracking (Decimal arithmetic)
      prompts/          Jinja2 prompt templates
    engine/
      pipeline.py       Orchestration (retry + circuit breaker)
    web/
      api.py            FastAPI endpoints
      watch_service.py  Background scan loop + DiagnoseStatus
    store.py            SQLite incident history
    models.py           Pydantic data models
    config.py           YAML + env var configuration
    logging_config.py   JSON structured logging
    cli.py              Click CLI entry point
  tests/
    conftest.py         Shared fixtures
    fixtures/           JSON fixture files for K8s data
  .github/workflows/    CI/CD pipelines
  deploy/k8s/           Kubernetes deployment manifests
  CHANGELOG.md
  CONTRIBUTING.md       (this file)
  SECURITY.md
```

---

## Making Changes

### Branching

Create a feature branch from `main`:

```bash
git checkout main
git pull upstream main
git checkout -b feat/my-feature
```

Branch naming conventions:
- `feat/description` - new feature
- `fix/description` - bug fix
- `docs/description` - documentation only
- `test/description` - test additions or fixes
- `refactor/description` - code refactoring

### Adding a New Collector

1. Create `src/argus_ops/collectors/<name>.py`
2. Subclass `BaseCollector` and implement `name`, `infra_type`, `is_available()`, `collect()`
3. Add to `src/argus_ops/collectors/__init__.py`
4. Register in `cli.py` and `config.py`
5. Add tests in `tests/test_collectors_<name>.py`

### Adding a New Analyzer

1. Create `src/argus_ops/analyzers/<name>.py`
2. Subclass `BaseAnalyzer` and implement `name` and `analyze()`
3. Add to `src/argus_ops/analyzers/__init__.py` `ALL_ANALYZERS` list
4. Add tests in `tests/test_analyzers.py`

---

## Testing

All tests must pass before submitting a PR. The project targets 80%+ coverage.

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=argus_ops --cov-report=term-missing

# Run a specific test file
pytest tests/test_pipeline.py -v

# Run a specific test class
pytest tests/test_api.py::TestApiDiagnose -v
```

### Test Requirements

- Every new feature must include unit tests.
- Mock external dependencies (K8s API, LiteLLM) -- tests must run without a cluster.
- Use `IncidentStore(db_path=":memory:")` for store tests.
- Use Click's `CliRunner` for CLI tests.
- Use FastAPI's `TestClient` for API endpoint tests.

---

## Code Style

Argus-Ops uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
# Check for lint errors
ruff check src/ tests/

# Auto-fix fixable issues
ruff check --fix src/ tests/
```

Key conventions:

- Line length: 100 characters
- Python 3.10+ syntax (union types with `|`, `match` statements)
- All public functions and classes must have docstrings
- Type annotations required for all function signatures
- Use `from __future__ import annotations` in every module

### Security

- Never log credentials, tokens, or API keys (even at DEBUG level)
- Validate and sanitize all external input (LLM responses, CLI args, config values)
- Use `Decimal` for monetary arithmetic, not `float`
- Event messages from K8s must pass through `_redact_event_message()` before sending to AI

---

## Submitting a Pull Request

1. Ensure all tests pass: `pytest`
2. Ensure lint is clean: `ruff check src/ tests/`
3. Update `CHANGELOG.md` under `[Unreleased]`
4. Push your branch and open a PR against `main`
5. Fill out the PR template completely
6. Link any related issues with `Closes #123`

### PR Checklist

- [ ] Tests added or updated for all changed behavior
- [ ] `pytest` passes with no failures
- [ ] `ruff check` passes with no errors
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Docstrings added for new public functions/classes
- [ ] No credentials or secrets committed

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/mason5052/argus-ops/issues/new) with:

- Argus-Ops version (`argus-ops --version`)
- Python version and OS
- Steps to reproduce
- Expected behavior vs actual behavior
- Relevant log output (run with `--log-level DEBUG`)

---

## Requesting Features

Open a [GitHub Issue](https://github.com/mason5052/argus-ops/issues/new) with:

- Use case: what problem are you trying to solve?
- Proposed solution (if you have one)
- Alternatives considered

---

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md)
for the responsible disclosure process.
