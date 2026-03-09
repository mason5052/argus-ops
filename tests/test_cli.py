"""Tests for the argus-ops CLI commands using Click CliRunner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role
from argus_ops.cli import cli
from argus_ops.models import Diagnosis, Finding, FindingCategory, Incident, InfraType, Severity


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def config_path(tmp_path):
    config = {
        "ai": {"provider": "openai", "model": "gpt-4o-mini", "api_key_env": "OPENAI_API_KEY"},
        "targets": {
            "kubernetes": {"enabled": True, "namespaces": [], "exclude_namespaces": []},
            "host": {"enabled": False, "paths": []},
            "docker": {"enabled": False},
            "git": {"enabled": False, "paths": [], "max_depth": 1},
            "terraform": {"enabled": False, "paths": [], "max_depth": 1},
            "github": {"enabled": False, "token_env": "GITHUB_TOKEN"},
            "aws": {"enabled": False},
        },
        "inventory": {"enabled": True, "paths": [], "max_depth": 1},
        "analyzers": {
            "resource": {},
            "pod_health": {},
            "node_health": {},
            "security": {},
            "storage": {},
            "cronjob": {},
            "network_policy": {},
            "configuration": {},
        },
        "auth": {
            "data_dir": str(tmp_path / "auth"),
            "session_ttl_hours": 24,
            "cookie_name": "argus_ops_session",
        },
        "audit": {"log_dir": str(tmp_path / "audit")},
        "logging": {"level": "WARNING"},
        "serve": {
            "host": "127.0.0.1",
            "port": 8080,
            "reload_interval": 30,
            "watch_interval": 30,
            "open_browser": False,
            "mcp": False,
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def sample_finding():
    return Finding(
        finding_id="CLI-FIND-001",
        category=FindingCategory.POD_HEALTH,
        severity=Severity.HIGH,
        title="CrashLoopBackOff: default/broken-pod",
        description="Container is crash-looping",
        target="k8s://default/broken-pod",
        infra_type=InfraType.KUBERNETES,
        evidence=["State: CrashLoopBackOff"],
        metrics={"restart_count": 5},
    )


@pytest.fixture
def sample_incident(sample_finding):
    diagnosis = Diagnosis(
        diagnosis_id="DIAG-CLI-001",
        finding_ids=["CLI-FIND-001"],
        root_cause="Memory limit too low",
        explanation="Container is OOMKilled repeatedly",
        confidence=0.9,
        recommendations=["Increase memory limit to 512Mi"],
    )
    return Incident(incident_id="INC-CLI-001", findings=[sample_finding], diagnosis=diagnosis)


def _invoke(runner: CliRunner, config_path: Path, args: list[str], **kwargs):
    return runner.invoke(cli, ["--config", str(config_path), *args], **kwargs)


def _extract_json(output: str) -> str:
    lines = output.strip().splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            return "\n".join(lines[index:])
    return output


class TestVersionFlag:
    def test_version_flag(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "argus-ops" in result.output


class TestScanCommand:
    def test_scan_json_output(self, runner, config_path, sample_finding):
        pipeline = MagicMock()
        pipeline.scan.return_value = [sample_finding]
        with patch("argus_ops.cli._build_kubernetes_collector", return_value=object()), patch(
            "argus_ops.cli._build_pipeline", return_value=pipeline
        ):
            result = _invoke(runner, config_path, ["scan", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert data[0]["finding_id"] == "CLI-FIND-001"

    def test_scan_handles_failure(self, runner, config_path):
        pipeline = MagicMock()
        pipeline.scan.side_effect = RuntimeError("cluster unavailable")
        with patch("argus_ops.cli._build_kubernetes_collector", return_value=object()), patch(
            "argus_ops.cli._build_pipeline", return_value=pipeline
        ):
            result = _invoke(runner, config_path, ["scan"])
        assert result.exit_code == 1


class TestInventoryAndCatalogCommands:
    def test_inventory_json_output(self, runner, config_path):
        summary = {
            "snapshot_count": 1,
            "latest_snapshot": "2026-03-08T10:00:00Z",
            "assets": [{"asset_type": "host", "name": "test-host", "infra_type": "host"}],
            "relations": [],
            "capabilities": [{"name": "host.identity"}],
        }
        with patch("argus_ops.cli._run_inventory", return_value=summary):
            result = _invoke(runner, config_path, ["inventory", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert len(data["assets"]) == 1

    def test_connectors_list(self, runner, config_path):
        collector = MagicMock()
        collector.name = "host"
        collector.is_available.return_value = True
        collector.provided_capabilities = ["host.identity"]
        with patch("argus_ops.cli._build_discovery_collectors", return_value=[collector]):
            result = _invoke(runner, config_path, ["connectors", "list"])
        assert result.exit_code == 0
        assert "host.identity" in result.output

    def test_workflows_and_plugins_list(self, runner, config_path):
        workflow_result = _invoke(runner, config_path, ["workflows", "list"])
        plugin_result = _invoke(runner, config_path, ["plugins", "list"])
        assert workflow_result.exit_code == 0
        assert plugin_result.exit_code == 0
        assert "gitops.pull_request" in workflow_result.output
        assert "host" in plugin_result.output


class TestPlanAndApplyCommands:
    def test_plan_read_only_json_output(self, runner, config_path):
        summary = {
            "snapshot_count": 1,
            "latest_snapshot": "2026-03-08T10:00:00Z",
            "assets": [
                {
                    "asset_id": "host:test",
                    "asset_type": "host",
                    "name": "test-host",
                    "infra_type": "host",
                }
            ],
            "relations": [],
            "capabilities": [{"name": "host.identity"}],
        }
        with patch("argus_ops.cli._run_inventory", return_value=summary), patch(
            "argus_ops.cli._build_kubernetes_collector", return_value=None
        ):
            result = _invoke(
                runner,
                config_path,
                ["plan", "summarize the infrastructure", "--output", "json"],
            )
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert data["intent"] == "read_only"

    def test_plan_mutating_requires_admin(self, runner, config_path):
        summary = {"snapshot_count": 0, "assets": [], "relations": [], "capabilities": []}
        with patch("argus_ops.cli._run_inventory", return_value=summary), patch(
            "argus_ops.cli._build_kubernetes_collector", return_value=None
        ):
            result = _invoke(runner, config_path, ["plan", "restart the broken pod"])
        assert result.exit_code == 1
        assert "not authenticated" in result.output.lower()

    def test_apply_admin_flow(self, runner, config_path):
        auth = Authenticator(data_dir=config_path.parent / "auth", session_ttl_hours=1)
        auth.user_store.create_user("admin1", "admin-pass", Role.admin)
        auth.login("admin1", "admin-pass")
        summary = {
            "snapshot_count": 1,
            "latest_snapshot": "2026-03-08T10:00:00Z",
            "assets": [
                {
                    "asset_id": "host:test",
                    "asset_type": "host",
                    "name": "test-host",
                    "infra_type": "host",
                }
            ],
            "relations": [],
            "capabilities": [{"name": "host.identity"}],
        }
        with patch("argus_ops.cli._run_inventory", return_value=summary), patch(
            "argus_ops.cli._build_kubernetes_collector", return_value=None
        ):
            plan_result = _invoke(
                runner,
                config_path,
                ["plan", "restart the broken pod", "--output", "json"],
            )
        assert plan_result.exit_code == 0
        plan_data = json.loads(_extract_json(plan_result.output))
        plan_id = plan_data["plan_id"]
        assert plan_data["metadata"]["workflow_export_path"]

        export_result = _invoke(runner, config_path, ["workflows", "export", "--plan-id", plan_id])
        assert export_result.exit_code == 0
        assert "workflow_id" in export_result.output
        assert plan_id.lower() in export_result.output.lower()

        pending_result = _invoke(
            runner,
            config_path,
            ["apply", "--plan-id", plan_id, "--output", "json"],
        )
        assert pending_result.exit_code == 1
        pending_data = json.loads(_extract_json(pending_result.output))
        assert pending_data["status"] == "approval_required"

        apply_result = _invoke(
            runner,
            config_path,
            ["apply", "--plan-id", plan_id, "--approve", "--output", "json"],
        )
        assert apply_result.exit_code == 0
        apply_data = json.loads(_extract_json(apply_result.output))
        assert apply_data["status"] == "completed"
        assert apply_data["execution_id"].startswith("EXEC-")
        assert apply_data["artifacts"]
        assert apply_data["verification_results"]

        executions_result = _invoke(runner, config_path, ["executions", "--limit", "5"])
        assert executions_result.exit_code == 0
        assert plan_id in executions_result.output


class TestDiagnoseCommand:
    def test_diagnose_requires_admin(self, runner, config_path):
        auth = Authenticator(data_dir=config_path.parent / "auth", session_ttl_hours=1)
        auth.user_store.create_user("viewer1", "viewer-pass", Role.viewer)
        auth.login("viewer1", "viewer-pass")
        result = _invoke(runner, config_path, ["diagnose"])
        assert result.exit_code == 1
        assert "admin" in result.output.lower()

    def test_diagnose_admin_json_output(self, runner, config_path, sample_finding, sample_incident):
        auth = Authenticator(data_dir=config_path.parent / "auth", session_ttl_hours=1)
        auth.user_store.create_user("admin1", "admin-pass", Role.admin)
        auth.login("admin1", "admin-pass")
        pipeline = MagicMock()
        pipeline.scan.return_value = [sample_finding]
        pipeline.diagnose.return_value = [sample_incident]
        pipeline.ai_provider = None
        with patch("argus_ops.cli._build_kubernetes_collector", return_value=object()), patch(
            "argus_ops.cli._build_pipeline", return_value=pipeline
        ):
            result = _invoke(runner, config_path, ["diagnose", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert data[0]["incident_id"] == "INC-CLI-001"


class TestBootstrapAndConfig:
    def test_bootstrap_creates_config(self, runner, tmp_path):
        path = tmp_path / "bootstrap.yaml"
        mock_auth = MagicMock()
        mock_auth.user_store.user_count.return_value = 0
        with patch("argus_ops.cli._get_authenticator", return_value=mock_auth), patch(
            "argus_ops.cli._run_inventory",
            return_value={"assets": [], "snapshot_count": 0, "capabilities": []},
        ):
            result = runner.invoke(
                cli,
                ["bootstrap", "--path", str(path)],
                input="admin\nsecret123\nsecret123\n",
            )
        assert result.exit_code == 0
        assert path.exists()

    def test_config_show(self, runner, config_path):
        result = _invoke(runner, config_path, ["config", "show"])
        assert result.exit_code == 0
        assert "ai:" in result.output






