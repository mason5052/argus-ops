"""Tests for core Pydantic data models."""

from __future__ import annotations

from argus_ops.models import (
    Diagnosis,
    Finding,
    FindingCategory,
    HealthSnapshot,
    Incident,
    InfraType,
    Severity,
)


class TestSeverityOrdering:
    def test_severity_enum_values(self):
        assert Severity.INFO == "info"
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            finding_id="TEST-001",
            category=FindingCategory.POD_HEALTH,
            severity=Severity.HIGH,
            title="Test finding",
            description="A test description",
            target="k8s://rpa/pod",
            infra_type=InfraType.KUBERNETES,
        )
        assert f.finding_id == "TEST-001"
        assert f.severity == Severity.HIGH
        assert f.evidence == []
        assert f.metrics == {}

    def test_finding_with_evidence(self):
        f = Finding(
            finding_id="TEST-002",
            category=FindingCategory.NODE_HEALTH,
            severity=Severity.CRITICAL,
            title="Node down",
            description="Node is not ready",
            target="k8s://node/worker-1",
            infra_type=InfraType.KUBERNETES,
            evidence=["Ready: False", "Reason: KubeletNotReady"],
        )
        assert len(f.evidence) == 2


class TestDiagnosis:
    def test_diagnosis_defaults(self):
        d = Diagnosis(
            diagnosis_id="DIAG-001",
            root_cause="Memory exhaustion",
            explanation="Node ran out of memory",
        )
        assert d.confidence == 0.0
        assert d.tokens_used == 0
        assert d.recommendations == []

    def test_diagnosis_with_confidence(self):
        d = Diagnosis(
            diagnosis_id="DIAG-002",
            root_cause="OOM",
            explanation="Container OOMKilled",
            confidence=0.9,
            recommendations=["Increase memory limit"],
        )
        assert d.confidence == 0.9
        assert len(d.recommendations) == 1


class TestIncident:
    def test_max_severity_empty(self):
        incident = Incident(incident_id="INC-001")
        assert incident.max_severity == Severity.INFO

    def test_max_severity_with_findings(self, sample_findings):
        incident = Incident(incident_id="INC-002", findings=sample_findings)
        assert incident.max_severity == Severity.CRITICAL

    def test_incident_status_default(self):
        incident = Incident(incident_id="INC-003")
        assert incident.status == "open"

    def test_incident_with_diagnosis(self, sample_finding):
        diagnosis = Diagnosis(
            diagnosis_id="DIAG-001",
            root_cause="CrashLoop",
            explanation="App keeps crashing",
            confidence=0.8,
        )
        incident = Incident(
            incident_id="INC-004",
            findings=[sample_finding],
            diagnosis=diagnosis,
        )
        assert incident.diagnosis is not None
        assert incident.diagnosis.confidence == 0.8


class TestHealthSnapshot:
    def test_snapshot_defaults(self):
        snap = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://rpa/pods",
        )
        assert snap.data == {}
        assert snap.metrics == {}
        assert snap.timestamp is not None
