"""Tests for the orchestration pipeline."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from argus_ops.engine.pipeline import Pipeline
from argus_ops.models import (
    Diagnosis,
)


def _make_mock_collector(snapshots):
    """Create a mock collector that returns the given snapshots."""
    collector = MagicMock()
    collector.name = "mock"
    collector.is_available.return_value = True
    collector.collect.return_value = snapshots
    return collector


def _make_mock_analyzer(findings):
    """Create a mock analyzer that returns the given findings."""
    analyzer = MagicMock()
    analyzer.name = "mock_analyzer"
    analyzer.analyze.return_value = findings
    return analyzer


def _make_mock_ai_provider(diagnosis):
    """Create a mock AI provider that returns the given diagnosis."""
    provider = MagicMock()
    provider.diagnose.return_value = diagnosis
    return provider


class TestPipelineScan:
    def test_scan_calls_collector_and_analyzer(self, node_snapshot, sample_findings):
        collector = _make_mock_collector([node_snapshot])
        analyzer = _make_mock_analyzer(sample_findings)

        pipeline = Pipeline(collectors=[collector], analyzers=[analyzer])
        findings = pipeline.scan()

        collector.is_available.assert_called_once()
        collector.collect.assert_called_once()
        analyzer.analyze.assert_called_once()
        assert len(findings) == len(sample_findings)

    def test_scan_skips_unavailable_collector(self, sample_findings):
        collector = _make_mock_collector([])
        collector.is_available.return_value = False
        analyzer = _make_mock_analyzer(sample_findings)

        pipeline = Pipeline(collectors=[collector], analyzers=[analyzer])
        pipeline.scan()

        collector.collect.assert_not_called()

    def test_scan_returns_empty_when_no_findings(self, node_snapshot):
        collector = _make_mock_collector([node_snapshot])
        analyzer = _make_mock_analyzer([])

        pipeline = Pipeline(collectors=[collector], analyzers=[analyzer])
        findings = pipeline.scan()

        assert findings == []

    def test_scan_aggregates_multiple_collectors(self, node_snapshot, pod_snapshot):
        c1 = _make_mock_collector([node_snapshot])
        c2 = _make_mock_collector([pod_snapshot])
        analyzer = _make_mock_analyzer([])

        pipeline = Pipeline(collectors=[c1, c2], analyzers=[analyzer])
        pipeline.scan()

        # Analyzer should receive snapshots from both collectors
        call_args = analyzer.analyze.call_args[0][0]
        assert len(call_args) == 2

    def test_scan_handles_collector_exception(self, sample_findings):
        failing_collector = MagicMock()
        failing_collector.name = "failing"
        failing_collector.is_available.return_value = True
        failing_collector.collect.side_effect = RuntimeError("Connection refused")

        analyzer = _make_mock_analyzer(sample_findings)
        pipeline = Pipeline(collectors=[failing_collector], analyzers=[analyzer])

        # Should not raise; logs error and continues
        findings = pipeline.scan()
        # Analyzer still called with empty snapshots
        assert isinstance(findings, list)


class TestPipelineDiagnose:
    def test_diagnose_calls_ai_provider(self, node_snapshot, sample_findings):
        diagnosis = Diagnosis(
            diagnosis_id="DIAG-001",
            root_cause="Memory issue",
            explanation="Node ran out of memory",
            confidence=0.9,
        )
        collector = _make_mock_collector([node_snapshot])
        analyzer = _make_mock_analyzer(sample_findings)
        ai = _make_mock_ai_provider(diagnosis)

        pipeline = Pipeline(collectors=[collector], analyzers=[analyzer], ai_provider=ai)
        incidents = pipeline.diagnose(sample_findings)

        ai.diagnose.assert_called()
        assert len(incidents) >= 1
        assert incidents[0].diagnosis is not None

    def test_diagnose_without_ai_provider(self, sample_findings):
        pipeline = Pipeline(collectors=[], analyzers=[])
        incidents = pipeline.diagnose(sample_findings)

        assert len(incidents) == 1
        assert incidents[0].findings == sample_findings
        assert incidents[0].diagnosis is None

    def test_diagnose_empty_findings_returns_empty(self):
        pipeline = Pipeline(collectors=[], analyzers=[])
        incidents = pipeline.diagnose([])
        assert incidents == []

    def test_diagnose_groups_by_infra_type(self, sample_findings):
        diagnosis = Diagnosis(
            diagnosis_id="DIAG-001",
            root_cause="Test",
            explanation="Test",
        )
        ai = _make_mock_ai_provider(diagnosis)
        pipeline = Pipeline(collectors=[], analyzers=[], ai_provider=ai)
        incidents = pipeline.diagnose(sample_findings)

        # All fixtures are KUBERNETES type, so should be in 1 group -> 1 incident
        assert len(incidents) == 1


class TestPipelineRunFull:
    def test_run_full_returns_empty_when_no_findings(self, node_snapshot):
        collector = _make_mock_collector([node_snapshot])
        analyzer = _make_mock_analyzer([])
        pipeline = Pipeline(collectors=[collector], analyzers=[analyzer])

        incidents = pipeline.run_full()
        assert incidents == []


class TestCircuitBreaker:
    def test_circuit_starts_closed(self):
        from argus_ops.engine.pipeline import CollectorCircuitBreaker
        cb = CollectorCircuitBreaker(name="test", failure_threshold=3)
        assert cb.state == "CLOSED"

    def test_circuit_opens_after_threshold(self):
        from argus_ops.engine.pipeline import CollectorCircuitBreaker

        cb = CollectorCircuitBreaker(name="test", failure_threshold=3, reset_timeout=9999)

        def _fail():
            raise RuntimeError("boom")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.call(_fail)

        assert cb.state == "OPEN"

    def test_circuit_open_rejects_calls(self):
        from argus_ops.engine.pipeline import CircuitOpen, CollectorCircuitBreaker

        cb = CollectorCircuitBreaker(name="test", failure_threshold=1, reset_timeout=9999)

        def _fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            cb.call(_fail)

        assert cb.state == "OPEN"
        with pytest.raises(CircuitOpen):
            cb.call(lambda: None)

    def test_circuit_half_open_after_timeout(self):
        from unittest.mock import MagicMock

        from argus_ops.engine.pipeline import CollectorCircuitBreaker

        mock_time = MagicMock()
        # Call sequence:
        #   [0] _record_failure() sets _opened_at = 0.0  (circuit opens)
        #   [1] next call() checks elapsed = 999.0 - 0.0 = 999s >= 60s -> HALF_OPEN
        mock_time.monotonic.side_effect = [0.0, 999.0]

        cb = CollectorCircuitBreaker(name="test", failure_threshold=1, reset_timeout=60.0)
        cb._time = mock_time

        def _fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            cb.call(_fail)

        assert cb.state == "OPEN"
        # Next call: timeout elapsed -> transitions OPEN -> HALF_OPEN, runs fn, succeeds -> CLOSED
        cb.call(lambda: None)
        assert cb.state == "CLOSED"

    def test_circuit_recovers_on_success(self):
        from argus_ops.engine.pipeline import CollectorCircuitBreaker

        cb = CollectorCircuitBreaker(name="test", failure_threshold=3, reset_timeout=9999)

        def _fail():
            raise RuntimeError("boom")

        # 2 failures -- not yet open
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_fail)

        # Success resets failure count
        cb.call(lambda: "ok")
        assert cb.state == "CLOSED"
        assert cb._failures == 0

    def test_pipeline_circuit_breaker_per_collector(self, node_snapshot, pod_snapshot):
        """Each collector gets its own independent circuit breaker."""
        c1 = _make_mock_collector([node_snapshot])
        c1.name = "collector_1"
        c2 = _make_mock_collector([pod_snapshot])
        c2.name = "collector_2"

        pipeline = Pipeline(collectors=[c1, c2], analyzers=[])
        cb1 = pipeline._get_circuit_breaker(c1)
        cb2 = pipeline._get_circuit_breaker(c2)
        assert cb1 is not cb2
