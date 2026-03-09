"""Tests that keep README, docs, CI, and public manifests aligned."""

from __future__ import annotations

from pathlib import Path

from argus_ops.cli import cli

README = Path("README.md")
VALUES = Path("deploy/helm/argus-ops/values.yaml")
RBAC = Path("deploy/helm/argus-ops/templates/rbac.yaml")
SECURITY = Path("SECURITY.md")
GITIGNORE = Path(".gitignore")
CI = Path(".github/workflows/ci.yml")
WORKFLOWS = Path(".github/workflows")
K8S_DEPLOY = Path("deploy/k8s/deployment.yaml")


def test_readme_mentions_current_core_commands():
    text = README.read_text(encoding="utf-8")
    required = [
        "argus-ops bootstrap",
        "argus-ops inventory",
        "argus-ops plan",
        "argus-ops apply",
        "argus-ops connectors list",
        "argus-ops workflows list",
        "argus-ops workflows export",
        "argus-ops executions",
        "argus-ops plugins list",
        "argus-ops serve --mcp",
        "viewer",
        "admin",
        "HostCollector",
        "DockerCollector",
        "GitRepoCollector",
        "TerraformCollector",
        "GitHubCollector",
        "AWSCollector",
        "KubernetesCollector",
        "/healthz",
        "/api/plan",
        "/api/apply",
        "/api/executions",
        "/api/workflows",
        "/api/workflows/export/{plan_id}",
        "/api/plugins",
        "/api/mcp/manifest",
        "rbac.profile=viewer",
        "rbac.profile=admin",
        "manual release",
        "./deploy/helm/argus-ops",
        "private repository",
    ]
    for item in required:
        assert item in text
    forbidden = [
        "mason530984/" + "argus-ops",
        "mason5052.github.io/" + "argus-ops",
    ]
    for item in forbidden:
        assert item not in text


def test_cli_help_exposes_documented_commands():
    from click.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    commands = [
        "bootstrap",
        "inventory",
        "plan",
        "apply",
        "executions",
        "plugins",
        "workflows",
        "connectors",
        "scan",
        "diagnose",
        "serve",
        "heal",
        "audit",
    ]
    for command in commands:
        assert command in result.output


def test_helm_defaults_and_rbac_match_readme_claims():
    values_text = VALUES.read_text(encoding="utf-8")
    rbac_text = RBAC.read_text(encoding="utf-8")
    assert "profile: viewer" in values_text
    assert "/healthz" in values_text
    assert "repository: argus-ops" in values_text
    assert 'tag: "manual"' in values_text
    assert "nodePort: null" in values_text
    assert 'if eq .Values.rbac.profile "admin"' in rbac_text


def test_security_docs_and_gitignore_match_public_repo_policy():
    security_text = SECURITY.read_text(encoding="utf-8")
    gitignore_text = GITIGNORE.read_text(encoding="utf-8")
    required_patterns = [
        "*.pem",
        "*.key",
        "*.crt",
        "*.p12",
        ".env.*",
        "config.yaml",
        "history.db",
        "inventory.db",
        "users.db",
        "sessions.db",
        "audit*.jsonl",
        "*.kubeconfig",
        "*credentials*",
    ]
    for pattern in required_patterns:
        assert pattern in security_text
        assert pattern in gitignore_text
    assert "All authenticated `/api/*` routes require authentication." in security_text
    assert "`/healthz` stays public" in security_text


def test_only_pr_validation_workflow_remains():
    workflow_names = sorted(path.name for path in WORKFLOWS.glob("*.yml"))
    assert workflow_names == ["ci.yml"]
    ci_text = CI.read_text(encoding="utf-8")
    assert "pull_request:" in ci_text
    assert "workflow_dispatch:" in ci_text
    assert "push:" not in ci_text
    assert "Secret pattern scan" in ci_text
    assert "Public repository policy checks" in ci_text
    assert "codecov" not in ci_text.lower()


def test_public_k8s_manifest_uses_public_safe_defaults():
    text = K8S_DEPLOY.read_text(encoding="utf-8")
    forbidden = [
        "10." + "1.1.81",
        "10." + "1.1.56",
        "node-pool:" + " dashboard",
        "type: NodePort",
        "nodePort:",
    ]
    for item in forbidden:
        assert item not in text
    assert "image: argus-ops:manual" in text
    assert "type: ClusterIP" in text

