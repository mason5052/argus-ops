"""Tests for FastAPI endpoints using httpx TestClient."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from argus_ops.models import (
    Diagnosis,
    Finding,
    FindingCategory,
    Incident,
    InfraType,
    Severity,
)
from argus_ops.web.api import create_app
from argus_ops.web.watch_service import DiagnoseStatus, WatchService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding():
    return Finding(
        finding_id="API-FIND-001",
        category=FindingCategory.POD_HEALTH,
        severity=Severity.HIGH,
        title="CrashLoopBackOff: rpa/broken-pod",
        description="Container is crash-looping with 8 restarts.",
        target="k8s://rpa/broken-pod",
        infra_type=InfraType.KUBERNETES,
        evidence=["State: CrashLoopBackOff"],
        metrics={"restart_count": 8},
    )


@pytest.fixture
def sample_incident(sample_finding):
    diag = Diagnosis(
        diagnosis_id="DIAG-API-001",
        finding_ids=["API-FIND-001"],
        root_cause="Container OOMKilled",
        explanation="Memory limit exceeded causing repeated crashes",
        confidence=0.88,
        recommendations=["Increase memory limit"],
        model_used="gpt-4o-mini",
        tokens_used=1500,
        cost_usd=0.001,
    )
    return Incident(
        incident_id="INC-API-0001",
        findings=[sample_finding],
        diagnosis=diag,
    )


def _make_watch_state(
    findings: list = None,
    nodes: list = None,
    trend: list = None,
    last_scan: str = None,
    error: str = None,
    diagnose_status: str = "idle",
    diagnose_error: str = None,
) -> dict[str, Any]:
    return {
        "findings": findings or [],
        "nodes": nodes or [],
        "trend": trend or [],
        "last_scan": last_scan or datetime.now(timezone.utc).isoformat(),
        "error": error,
        "interval": 30,
        "diagnose_status": diagnose_status,
        "diagnose_error": diagnose_error,
    }


@pytest.fixture
def mock_watch(sample_finding, sample_incident):
    watch = MagicMock(spec=WatchService)
    watch.get_state.return_value = _make_watch_state(findings=[sample_finding])
    watch.get_incidents.return_value = [sample_incident]
    watch.diagnose_now.return_value = [sample_incident]
    return watch


@pytest.fixture
def client(mock_watch):
    app = create_app(watch=mock_watch, cfg={"serve": {"reload_interval": 15}})
    return TestClient(app)


# ---------------------------------------------------------------------------
# /api/status
# ---------------------------------------------------------------------------

class TestApiStatus:
    def test_status_ok(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "last_scan" in data
        assert "server_time" in data
        assert "diagnose_status" in data

    def test_status_includes_diagnose_status(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state(diagnose_status="running")
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.json()["diagnose_status"] == "running"

    def test_status_includes_error(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state(error="Connection refused")
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.json()["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# /api/scan
# ---------------------------------------------------------------------------

class TestApiScan:
    def test_scan_returns_findings(self, client, sample_finding):
        resp = client.get("/api/scan")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert data["total"] == 1
        assert data["findings"][0]["finding_id"] == "API-FIND-001"

    def test_scan_empty_findings(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state(findings=[])
        resp = client.get("/api/scan")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
        assert resp.json()["findings"] == []


# ---------------------------------------------------------------------------
# /api/nodes
# ---------------------------------------------------------------------------

class TestApiNodes:
    def test_nodes_returns_node_list(self, client, mock_watch):
        nodes = [
            {"name": "worker-1", "conditions": {"Ready": {"status": "True"}}},
            {"name": "worker-2", "conditions": {"Ready": {"status": "False"}}},
        ]
        mock_watch.get_state.return_value = _make_watch_state(nodes=nodes)
        resp = client.get("/api/nodes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["ready"] == 1

    def test_nodes_empty(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state(nodes=[])
        resp = client.get("/api/nodes")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
        assert resp.json()["ready"] == 0


# ---------------------------------------------------------------------------
# /api/diagnoses
# ---------------------------------------------------------------------------

class TestApiDiagnoses:
    def test_diagnoses_returns_incidents(self, client, sample_incident):
        resp = client.get("/api/diagnoses")
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data
        assert data["total"] == 1
        inc = data["incidents"][0]
        assert inc["incident_id"] == "INC-API-0001"
        assert inc["max_severity"] == "high"
        assert inc["diagnosis"] is not None
        assert inc["diagnosis"]["root_cause"] == "Container OOMKilled"

    def test_diagnoses_empty(self, client, mock_watch):
        mock_watch.get_incidents.return_value = []
        resp = client.get("/api/diagnoses")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_diagnoses_uses_sqlite_store(self, client, mock_watch):
        resp = client.get("/api/diagnoses")
        assert resp.status_code == 200
        # Verify get_incidents() was called (SQLite-backed), not get_state()["incidents"]
        mock_watch.get_incidents.assert_called_once()


# ---------------------------------------------------------------------------
# /api/trend
# ---------------------------------------------------------------------------

class TestApiTrend:
    def test_trend_returns_data_points(self, client, mock_watch):
        trend = [
            {"ts": "2026-02-23T10:00:00Z", "critical": 0, "high": 2, "medium": 1, "low": 0, "info": 3},
            {"ts": "2026-02-23T10:00:30Z", "critical": 1, "high": 2, "medium": 1, "low": 0, "info": 3},
        ]
        mock_watch.get_state.return_value = _make_watch_state(trend=trend)
        resp = client.get("/api/trend")
        assert resp.status_code == 200
        assert len(resp.json()["trend"]) == 2

    def test_trend_empty(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state(trend=[])
        resp = client.get("/api/trend")
        assert resp.status_code == 200
        assert resp.json()["trend"] == []


# ---------------------------------------------------------------------------
# POST /api/diagnose
# ---------------------------------------------------------------------------

class TestApiDiagnose:
    def test_diagnose_success(self, client, sample_incident):
        resp = client.post("/api/diagnose")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["total"] == 1
        assert data["incidents"][0]["incident_id"] == "INC-API-0001"

    def test_diagnose_already_running(self, client, mock_watch):
        mock_watch.diagnose_now.side_effect = RuntimeError(
            "AI diagnosis is already in progress."
        )
        resp = client.post("/api/diagnose")
        assert resp.status_code == 503
        assert "progress" in resp.json()["detail"].lower()

    def test_diagnose_no_ai_provider(self, client, mock_watch):
        mock_watch.diagnose_now.side_effect = RuntimeError(
            "No AI provider configured."
        )
        resp = client.post("/api/diagnose")
        assert resp.status_code == 503

    def test_diagnose_returns_empty_when_no_findings(self, client, mock_watch):
        mock_watch.diagnose_now.return_value = []
        resp = client.post("/api/diagnose")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# /api/settings
# ---------------------------------------------------------------------------

class TestApiSettings:
    def test_get_settings(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state()
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert "watch_interval" in data
        assert "reload_interval" in data
        assert data["reload_interval"] == 15  # from fixture cfg

    def test_update_watch_interval(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state()
        resp = client.post("/api/settings", json={"watch_interval": 60})
        assert resp.status_code == 200
        mock_watch.set_interval.assert_called_once_with(60)

    def test_update_reload_interval(self, client, mock_watch):
        mock_watch.get_state.return_value = _make_watch_state()
        resp = client.post("/api/settings", json={"reload_interval": 45})
        assert resp.status_code == 200
        assert resp.json()["reload_interval"] == 45

    def test_update_interval_too_small(self, client, mock_watch):
        mock_watch.set_interval.side_effect = ValueError("Interval must be at least 10 seconds")
        resp = client.post("/api/settings", json={"watch_interval": 5})
        assert resp.status_code == 422

    def test_update_interval_below_minimum_validation(self, client):
        # Pydantic field validator enforces ge=10
        resp = client.post("/api/settings", json={"watch_interval": 1})
        assert resp.status_code == 422
