"""Tests for the dual audit trail system."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from argus_ops.audit.logger import AuditLogger
from argus_ops.audit.models import ApprovalRecord, AuditRecord, K8sAuditEvent, RiskLevel


class TestAuditRecord:
    def test_create_record(self):
        rec = AuditRecord(
            actor="mason",
            source="heal",
            action="restart_pod",
            target="pod/nginx (namespace: default)",
            reason="CrashLoopBackOff detected",
            risk_level=RiskLevel.low,
            command="kubectl delete pod nginx -n default",
        )
        assert rec.actor == "mason"
        assert rec.risk_level == RiskLevel.low
        assert rec.dry_run is False
        assert len(rec.id) == 12

    def test_risk_level_ordering(self):
        assert RiskLevel.low < RiskLevel.medium
        assert RiskLevel.medium < RiskLevel.high
        assert RiskLevel.high < RiskLevel.critical
        assert RiskLevel.critical > RiskLevel.low


class TestAuditLogger:
    @pytest.fixture
    def logger(self, tmp_path):
        return AuditLogger(audit_dir=tmp_path / "audit")

    def test_log_and_query(self, logger):
        rec = AuditRecord(
            actor="tester",
            source="heal",
            action="restart_pod",
            target="pod/test",
            risk_level=RiskLevel.low,
        )
        logger.log(rec)

        results = logger.query()
        assert len(results) == 1
        assert results[0].actor == "tester"
        assert results[0].action == "restart_pod"

    def test_query_filter_by_actor(self, logger):
        logger.log(AuditRecord(actor="alice", action="restart_pod", source="heal"))
        logger.log(AuditRecord(actor="bob", action="scale_deployment", source="heal"))

        results = logger.query(actor="alice")
        assert len(results) == 1
        assert results[0].actor == "alice"

    def test_query_filter_by_risk(self, logger):
        logger.log(AuditRecord(actor="a", action="a1", source="heal", risk_level=RiskLevel.low))
        logger.log(AuditRecord(actor="a", action="a2", source="heal", risk_level=RiskLevel.high))

        results = logger.query(risk_level=RiskLevel.high)
        assert len(results) == 1
        assert results[0].action == "a2"

    def test_export_csv(self, logger, tmp_path):
        logger.log(AuditRecord(actor="csv-test", action="export", source="heal"))
        csv_path = tmp_path / "export.csv"
        count = logger.export_csv(csv_path)
        assert count == 1
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "csv-test" in content
        assert "export" in content

    def test_empty_query(self, logger):
        results = logger.query()
        assert results == []


class TestK8sAuditEvent:
    def test_create_event(self):
        ev = K8sAuditEvent(
            user="system:serviceaccount:default:deployer",
            verb="create",
            resource_kind="Deployment",
            resource_name="nginx",
            namespace="default",
            response_code=201,
        )
        assert ev.user == "system:serviceaccount:default:deployer"
        assert ev.verb == "create"
        assert ev.argus_ops_record_id == ""
