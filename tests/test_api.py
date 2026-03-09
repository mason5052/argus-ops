"""Tests for FastAPI endpoints using TestClient."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from argus_ops.audit.logger import AuditLogger
from argus_ops.auth.authenticator import Authenticator
from argus_ops.auth.models import Role
from argus_ops.automation import AutomationService
from argus_ops.models import Diagnosis, Finding, FindingCategory, Incident, InfraType, Severity
from argus_ops.web.api import create_app
from argus_ops.web.watch_service import WatchService


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
    diagnosis = Diagnosis(
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
        diagnosis=diagnosis,
    )


def _make_watch_state(
    *,
    findings=None,
    nodes=None,
    trend=None,
    inventory=None,
    diagnose_status="idle",
):
    return {
        "findings": findings or [],
        "nodes": nodes or [],
        "trend": trend or [],
        "inventory": inventory or {"assets": [], "capabilities": [], "relations": []},
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "error": None,
        "interval": 30,
        "diagnose_status": diagnose_status,
        "diagnose_error": None,
    }


@pytest.fixture
def auth(tmp_path):
    auth = Authenticator(data_dir=tmp_path / "auth", session_ttl_hours=2)
    auth.user_store.create_user("viewer1", "viewer-pass", Role.viewer)
    auth.user_store.create_user("admin1", "admin-pass", Role.admin)
    return auth


@pytest.fixture
def audit_logger(tmp_path):
    return AuditLogger(audit_dir=tmp_path / "audit")


@pytest.fixture
def automation_service(tmp_path):
    return AutomationService(data_dir=tmp_path / "automation")


@pytest.fixture
def mock_watch(sample_finding, sample_incident):
    watch = MagicMock(spec=WatchService)
    inventory = {
        "snapshot_count": 2,
        "latest_snapshot": datetime.now(timezone.utc).isoformat(),
        "assets": [
            {
                "asset_id": "host:test",
                "asset_type": "host",
                "name": "test-host",
                "infra_type": "host",
                "tags": [],
            }
        ],
        "relations": [],
        "capabilities": [{"name": "host.identity", "collector_name": "host"}],
    }
    watch.get_state.return_value = _make_watch_state(findings=[sample_finding], inventory=inventory)
    watch.get_incidents.return_value = [sample_incident]
    watch.get_inventory_summary.return_value = inventory
    watch.get_pending_events.return_value = []
    watch.diagnose_now.return_value = [sample_incident]
    return watch


@pytest.fixture
def client(mock_watch, auth, audit_logger, automation_service):
    app = create_app(
        watch=mock_watch,
        cfg={
            "serve": {"reload_interval": 15, "mcp": True},
            "auth": {"data_dir": None},
            "audit": {"log_dir": None},
        },
        auth=auth,
        audit_logger=audit_logger,
        automation_service=automation_service,
    )
    return TestClient(app)


def _login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


class TestPublicEndpoints:
    def test_healthz_is_public(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_api_requires_auth(self, client):
        response = client.get("/api/status")
        assert response.status_code == 401

    def test_docs_require_admin(self, client):
        response = client.get("/docs")
        assert response.status_code == 401


class TestViewerEndpoints:
    def test_viewer_can_read_status_and_inventory(self, client):
        _login(client, "viewer1", "viewer-pass")
        status_response = client.get("/api/status")
        inventory_response = client.get("/api/inventory")
        assert status_response.status_code == 200
        assert inventory_response.status_code == 200
        assert inventory_response.json()["asset_count"] == 1
        assert status_response.json()["mcp_enabled"] is True

    def test_viewer_can_read_scan_and_diagnoses(self, client):
        _login(client, "viewer1", "viewer-pass")
        scan_response = client.get("/api/scan")
        diagnoses_response = client.get("/api/diagnoses")
        assert scan_response.status_code == 200
        assert scan_response.json()["total"] == 1
        assert diagnoses_response.status_code == 200
        assert diagnoses_response.json()["total"] == 1

    def test_viewer_can_read_mcp_manifest(self, client):
        _login(client, "viewer1", "viewer-pass")
        response = client.get("/api/mcp/manifest")
        assert response.status_code == 200
        assert response.json()["name"] == "argus-ops"

    def test_viewer_can_create_read_only_plan_and_read_catalogs(self, client):
        _login(client, "viewer1", "viewer-pass")
        plan_response = client.post(
            "/api/plan",
            json={"goal": "summarize the discovered infrastructure", "mode": "auto", "targets": []},
        )
        assert plan_response.status_code == 200
        plan_id = plan_response.json()["plan"]["plan_id"]

        workflows_response = client.get("/api/workflows")
        plugins_response = client.get("/api/plugins")
        plans_response = client.get("/api/plans")
        executions_response = client.get("/api/executions")
        export_response = client.get(f"/api/workflows/export/{plan_id}")

        assert plan_response.json()["plan"]["intent"] == "read_only"
        assert workflows_response.status_code == 200
        assert plugins_response.status_code == 200
        assert plans_response.status_code == 200
        assert executions_response.status_code == 200
        assert export_response.status_code == 200
        assert plans_response.json()["total"] >= 1
        assert executions_response.json()["total"] == 0
        assert export_response.json()["workflow"]["metadata"]["plan_id"] == plan_id

    def test_viewer_cannot_create_mutating_plan(self, client):
        _login(client, "viewer1", "viewer-pass")
        response = client.post(
            "/api/plan",
            json={"goal": "restart the broken pod", "mode": "direct", "targets": []},
        )
        assert response.status_code == 403

    def test_viewer_cannot_run_diagnose(self, client):
        _login(client, "viewer1", "viewer-pass")
        response = client.post("/api/diagnose")
        assert response.status_code == 403


class TestAdminEndpoints:
    def test_admin_can_run_diagnose(self, client):
        _login(client, "admin1", "admin-pass")
        response = client.post("/api/diagnose")
        assert response.status_code == 200
        assert response.json()["total"] == 1

    def test_admin_can_manage_users(self, client):
        _login(client, "admin1", "admin-pass")
        create_response = client.post(
            "/api/admin/users",
            json={"username": "new-user", "password": "new-pass", "role": "viewer"},
        )
        assert create_response.status_code == 200

        list_response = client.get("/api/admin/users")
        assert list_response.status_code == 200
        assert any(user["username"] == "new-user" for user in list_response.json()["users"])

        patch_response = client.patch(
            "/api/admin/users/new-user",
            json={"role": "admin", "is_active": False},
        )
        assert patch_response.status_code == 200

        password_response = client.post(
            "/api/admin/users/new-user/password",
            json={"password": "reset-pass"},
        )
        assert password_response.status_code == 200

        delete_response = client.delete("/api/admin/users/new-user")
        assert delete_response.status_code == 200

    def test_admin_can_access_docs(self, client):
        _login(client, "admin1", "admin-pass")
        response = client.get("/docs")
        assert response.status_code == 200
        assert "Argus-Ops API Docs" in response.text

    def test_admin_can_read_audit(self, client):
        _login(client, "admin1", "admin-pass")
        client.get("/api/status")
        response = client.get("/api/admin/audit")
        assert response.status_code == 200
        assert "records" in response.json()

    def test_admin_can_plan_and_apply(self, client):
        _login(client, "admin1", "admin-pass")
        plan_response = client.post(
            "/api/plan",
            json={"goal": "restart the broken pod", "mode": "direct", "targets": ["host:test"]},
        )
        assert plan_response.status_code == 200
        plan_payload = plan_response.json()["plan"]
        plan_id = plan_payload["plan_id"]
        assert plan_payload["metadata"]["workflow_export_path"]

        approval_response = client.post(
            "/api/apply",
            json={"plan_id": plan_id, "approve": False, "direct": True},
        )
        assert approval_response.status_code == 409

        export_response = client.get(f"/api/workflows/export/{plan_id}")
        assert export_response.status_code == 200

        apply_response = client.post(
            "/api/apply",
            json={"plan_id": plan_id, "approve": True, "direct": True},
        )
        assert apply_response.status_code == 200
        apply_payload = apply_response.json()
        assert apply_payload["status"] == "completed"
        assert apply_payload["execution_id"].startswith("EXEC-")
        assert apply_payload["artifacts"]
        assert apply_payload["verification_results"]
        assert apply_payload["workflow_export_path"]

        executions_response = client.get("/api/executions")
        assert executions_response.status_code == 200
        assert executions_response.json()["total"] >= 1


class TestAuthFlow:
    def test_login_and_logout(self, client):
        login_response = client.post(
            "/api/auth/login",
            json={"username": "viewer1", "password": "viewer-pass"},
        )
        assert login_response.status_code == 200

        me_response = client.get("/api/auth/me")
        assert me_response.status_code == 200
        assert me_response.json()["username"] == "viewer1"

        logout_response = client.post("/api/auth/logout")
        assert logout_response.status_code == 200

        after_logout = client.get("/api/auth/me")
        assert after_logout.status_code == 401


