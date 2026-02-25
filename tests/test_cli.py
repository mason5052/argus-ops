"""Tests for the argus-ops CLI commands using Click's CliRunner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from argus_ops.cli import cli
from argus_ops.models import (
    Diagnosis,
    Finding,
    FindingCategory,
    Incident,
    InfraType,
    Severity,
)

# CLI imports these inside function bodies so they must be patched at the source module
_PATCH_COLLECTOR = "argus_ops.collectors.k8s.KubernetesCollector"
_PATCH_PIPELINE = "argus_ops.engine.pipeline.Pipeline"
_PATCH_AI = "argus_ops.ai.provider.LiteLLMProvider"


@pytest.fixture
def runner():
    return CliRunner()


def _extract_json(output: str) -> str:
    """Extract the JSON portion from CLI output that may contain non-JSON status lines."""
    lines = output.strip().splitlines()
    # Find first line that starts a JSON value ([ or {)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            return "\n".join(lines[i:])
    return output


@pytest.fixture
def mock_findings():
    return [
        Finding(
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
    ]


@pytest.fixture
def mock_incident(mock_findings):
    diag = Diagnosis(
        diagnosis_id="DIAG-CLI-001",
        finding_ids=["CLI-FIND-001"],
        root_cause="Memory limit too low",
        explanation="Container is OOMKilled repeatedly",
        confidence=0.9,
        recommendations=["Increase memory limit to 512Mi"],
    )
    return Incident(
        incident_id="INC-CLI-001",
        findings=mock_findings,
        diagnosis=diag,
    )


class TestVersionFlag:
    def test_version_flag(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "argus-ops" in result.output


class TestScanCommand:
    def _make_pipeline_mock(self, findings):
        mock_pipeline = MagicMock()
        mock_pipeline.scan.return_value = findings
        return mock_pipeline

    def test_scan_console_output(self, runner, mock_findings):
        mock_pipeline = self._make_pipeline_mock(mock_findings)
        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 0

    def test_scan_json_output(self, runner, mock_findings):
        mock_pipeline = self._make_pipeline_mock(mock_findings)
        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["scan", "--output", "json"])
        assert result.exit_code == 0
        output_data = json.loads(_extract_json(result.output))
        assert isinstance(output_data, list)
        assert len(output_data) == 1
        assert output_data[0]["finding_id"] == "CLI-FIND-001"

    def test_scan_no_findings(self, runner):
        mock_pipeline = self._make_pipeline_mock([])
        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["scan", "--output", "json"])
        assert result.exit_code == 0
        assert json.loads(_extract_json(result.output)) == []

    def test_scan_severity_filter(self, runner, mock_findings):
        mock_pipeline = self._make_pipeline_mock(mock_findings)
        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            # Filter by critical -- HIGH finding should be excluded
            result = runner.invoke(cli, ["scan", "--output", "json", "--severity", "critical"])
        assert result.exit_code == 0
        output_data = json.loads(_extract_json(result.output))
        assert output_data == []

    def test_scan_handles_pipeline_exception(self, runner):
        mock_pipeline = MagicMock()
        mock_pipeline.scan.side_effect = RuntimeError("K8s API unreachable")
        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 1

    def test_scan_namespace_flag(self, runner, mock_findings):
        mock_pipeline = self._make_pipeline_mock(mock_findings)
        captured_k8s_cfg = {}

        def _capture_collector(config=None, **kwargs):
            if config:
                captured_k8s_cfg.update(config)
            return MagicMock()

        with patch(_PATCH_COLLECTOR, side_effect=_capture_collector), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            runner.invoke(cli, ["scan", "-n", "rpa", "-n", "default"])

        assert "rpa" in captured_k8s_cfg.get("namespaces", [])
        assert "default" in captured_k8s_cfg.get("namespaces", [])


class TestDiagnoseCommand:
    def test_diagnose_with_findings(self, runner, mock_findings, mock_incident):
        mock_pipeline = MagicMock()
        mock_pipeline.scan.return_value = mock_findings
        mock_pipeline.diagnose.return_value = [mock_incident]

        mock_ai = MagicMock()
        mock_ai.cost_tracker.calls = []

        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_AI, return_value=mock_ai), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["diagnose", "--output", "json"])

        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert isinstance(data, list)
        assert data[0]["incident_id"] == "INC-CLI-001"

    def test_diagnose_no_findings(self, runner):
        mock_pipeline = MagicMock()
        mock_pipeline.scan.return_value = []
        mock_ai = MagicMock()
        mock_ai.cost_tracker.calls = []

        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_AI, return_value=mock_ai), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            result = runner.invoke(cli, ["diagnose"])

        assert result.exit_code == 0

    def test_diagnose_model_override(self, runner, mock_findings, mock_incident):
        mock_pipeline = MagicMock()
        mock_pipeline.scan.return_value = mock_findings
        mock_pipeline.diagnose.return_value = [mock_incident]
        captured_ai_cfg = {}

        def _capture_ai(config=None, **kwargs):
            if config:
                captured_ai_cfg.update(config)
            m = MagicMock()
            m.cost_tracker.calls = []
            return m

        with patch(_PATCH_COLLECTOR), \
             patch(_PATCH_AI, side_effect=_capture_ai), \
             patch(_PATCH_PIPELINE, return_value=mock_pipeline):
            runner.invoke(cli, ["diagnose", "--model", "claude-sonnet-4-6"])

        assert captured_ai_cfg.get("model") == "claude-sonnet-4-6"


class TestConfigCommand:
    def _mock_auth(self):
        """Return a mock Authenticator that simulates empty user store."""
        mock_auth = MagicMock()
        mock_auth.user_store.user_count.return_value = 0
        return mock_auth

    def test_config_init_creates_file(self, runner, tmp_path):
        config_path = tmp_path / "test-config.yaml"
        mock_auth = self._mock_auth()
        with patch("argus_ops.auth.authenticator.Authenticator", return_value=mock_auth):
            result = runner.invoke(
                cli,
                ["config", "init", "--path", str(config_path)],
                input="admin\nsecret123\nsecret123\n",
            )
        assert result.exit_code == 0
        assert config_path.exists()
        content = config_path.read_text()
        assert "argus" in content.lower() or "ai" in content.lower()

    def test_config_init_refuses_overwrite_without_force(self, runner, tmp_path):
        config_path = tmp_path / "existing.yaml"
        config_path.write_text("existing: config")
        result = runner.invoke(cli, ["config", "init", "--path", str(config_path)])
        assert result.exit_code == 1
        assert "force" in result.output.lower() or "exists" in result.output.lower()

    def test_config_init_force_overwrites(self, runner, tmp_path):
        config_path = tmp_path / "existing.yaml"
        config_path.write_text("old: content")
        mock_auth = self._mock_auth()
        with patch("argus_ops.auth.authenticator.Authenticator", return_value=mock_auth):
            result = runner.invoke(
                cli,
                ["config", "init", "--path", str(config_path), "--force"],
                input="admin\nsecret123\nsecret123\n",
            )
        assert result.exit_code == 0
        assert "old: content" not in config_path.read_text()

    def test_config_show(self, runner):
        result = runner.invoke(cli, ["config", "show"])
        assert result.exit_code == 0
        assert "ai:" in result.output or "logging:" in result.output


class TestCircuitBreakerPipeline:
    def test_pipeline_circuit_breaker_opens_after_failures(self):
        """Verify circuit breaker opens after 3 consecutive collector failures."""
        from argus_ops.engine.pipeline import Pipeline

        failing_collector = MagicMock()
        failing_collector.name = "flaky"
        failing_collector.is_available.return_value = True
        failing_collector.collect.side_effect = RuntimeError("timeout")

        pipeline = Pipeline(collectors=[failing_collector], analyzers=[])

        # Three calls each fail through retry -> open the circuit
        for _ in range(3):
            pipeline.collect()

        cb = pipeline._get_circuit_breaker(failing_collector)
        assert cb.state == "OPEN"

    def test_pipeline_retry_calls_collector_multiple_times(self):
        """Verify retry logic calls collector up to _RETRY_ATTEMPTS times."""
        from argus_ops.engine.pipeline import Pipeline

        call_count = 0

        def _fail_twice_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("transient error")
            return []

        collector = MagicMock()
        collector.name = "retry_test"
        collector.is_available.return_value = True
        collector.collect.side_effect = _fail_twice_then_succeed

        pipeline = Pipeline(collectors=[collector], analyzers=[])
        pipeline.collect()

        # Should have been called 3 times (2 failures + 1 success)
        assert collector.collect.call_count == 3
