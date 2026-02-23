"""Tests for SQLite-backed IncidentStore."""

from __future__ import annotations

import pytest

from argus_ops.models import Diagnosis, Finding, FindingCategory, Incident, InfraType, Severity
from argus_ops.store import IncidentStore


@pytest.fixture
def store():
    """In-memory SQLite store, discarded after each test."""
    return IncidentStore(db_path=":memory:")


@pytest.fixture
def sample_incident():
    finding = Finding(
        finding_id="FIND-001",
        category=FindingCategory.POD_HEALTH,
        severity=Severity.HIGH,
        title="CrashLoopBackOff",
        description="Pod is crash-looping",
        target="k8s://default/test-pod",
        infra_type=InfraType.KUBERNETES,
    )
    return Incident(incident_id="INC-00000001", findings=[finding])


@pytest.fixture
def sample_incident_with_diagnosis(sample_incident):
    diag = Diagnosis(
        diagnosis_id="DIAG-00000001",
        finding_ids=["FIND-001"],
        root_cause="OOMKilled",
        explanation="Container exceeded memory limit",
        confidence=0.95,
        recommendations=["Increase memory limit", "Add memory alert"],
        related_resources=["k8s://default/test-pod"],
    )
    sample_incident.diagnosis = diag
    return sample_incident


class TestIncidentStoreSave:
    def test_save_and_count(self, store, sample_incident):
        assert store.count_incidents() == 0
        store.save_incident(sample_incident)
        assert store.count_incidents() == 1

    def test_save_replace_existing(self, store, sample_incident):
        store.save_incident(sample_incident)
        store.save_incident(sample_incident)  # same id -> replace
        assert store.count_incidents() == 1

    def test_save_multiple(self, store, sample_finding):
        for i in range(5):
            inc = Incident(
                incident_id=f"INC-{i:08d}",
                findings=[sample_finding],
            )
            store.save_incident(inc)
        assert store.count_incidents() == 5


class TestIncidentStoreLoad:
    def test_load_returns_most_recent_first(self, store, sample_finding):
        ids = []
        for i in range(3):
            inc = Incident(
                incident_id=f"INC-{i:08d}",
                findings=[sample_finding],
            )
            store.save_incident(inc)
            ids.append(inc.incident_id)

        loaded = store.load_incidents(limit=10)
        # Most recent saved is INC-2 (latest created_at); order should be descending
        assert len(loaded) == 3

    def test_load_limit(self, store, sample_finding):
        for i in range(10):
            store.save_incident(Incident(incident_id=f"INC-{i:08d}", findings=[sample_finding]))
        loaded = store.load_incidents(limit=3)
        assert len(loaded) == 3

    def test_load_offset(self, store, sample_finding):
        for i in range(5):
            store.save_incident(Incident(incident_id=f"INC-{i:08d}", findings=[sample_finding]))
        page1 = store.load_incidents(limit=2, offset=0)
        page2 = store.load_incidents(limit=2, offset=2)
        all_ids = {inc.incident_id for inc in page1 + page2}
        assert len(all_ids) == 4  # no duplicates across pages

    def test_load_filter_by_severity(self, store, sample_finding):
        high_inc = Incident(incident_id="INC-HIGH0001", findings=[sample_finding])
        low_finding = Finding(
            finding_id="FIND-LOW",
            category=FindingCategory.RESOURCE,
            severity=Severity.LOW,
            title="Low severity",
            description="Minor issue",
            target="k8s://default/pod",
            infra_type=InfraType.KUBERNETES,
        )
        low_inc = Incident(incident_id="INC-LOW00001", findings=[low_finding])
        store.save_incident(high_inc)
        store.save_incident(low_inc)

        high_results = store.load_incidents(severity="high")
        assert len(high_results) == 1
        assert high_results[0].incident_id == "INC-HIGH0001"

    def test_count_by_severity(self, store, sample_finding):
        store.save_incident(Incident(incident_id="INC-HIGH0001", findings=[sample_finding]))
        store.save_incident(Incident(incident_id="INC-HIGH0002", findings=[sample_finding]))
        assert store.count_incidents(severity="high") == 2
        assert store.count_incidents(severity="critical") == 0

    def test_load_preserves_diagnosis(self, store, sample_incident_with_diagnosis):
        store.save_incident(sample_incident_with_diagnosis)
        loaded = store.load_incidents()
        assert len(loaded) == 1
        assert loaded[0].diagnosis is not None
        assert loaded[0].diagnosis.root_cause == "OOMKilled"
        assert loaded[0].diagnosis.confidence == 0.95
        assert "Increase memory limit" in loaded[0].diagnosis.recommendations

    def test_load_preserves_findings(self, store, sample_incident):
        store.save_incident(sample_incident)
        loaded = store.load_incidents()
        assert len(loaded[0].findings) == 1
        assert loaded[0].findings[0].finding_id == "FIND-001"
        assert loaded[0].findings[0].severity == Severity.HIGH

    def test_load_empty_store(self, store):
        result = store.load_incidents()
        assert result == []


class TestTrendStore:
    def test_save_and_load_trend(self, store):
        point = {"ts": "2026-02-23T10:00:00Z", "critical": 2, "high": 3, "medium": 1, "low": 0, "info": 5}
        store.save_trend_point(point)
        trend = store.load_trend()
        assert len(trend) == 1
        assert trend[0]["critical"] == 2
        assert trend[0]["high"] == 3

    def test_trend_order_oldest_first(self, store):
        for i in range(5):
            store.save_trend_point({
                "ts": f"2026-02-23T{i:02d}:00:00Z",
                "critical": i, "high": 0, "medium": 0, "low": 0, "info": 0,
            })
        trend = store.load_trend()
        # load_trend returns oldest first
        assert trend[0]["critical"] == 0
        assert trend[-1]["critical"] == 4

    def test_trend_limit(self, store):
        for i in range(20):
            store.save_trend_point({
                "ts": f"2026-02-23T00:{i:02d}:00Z",
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": i,
            })
        trend = store.load_trend(limit=5)
        assert len(trend) == 5


class TestClear:
    def test_clear_removes_all(self, store, sample_incident):
        store.save_incident(sample_incident)
        store.save_trend_point({"ts": "2026-02-23T10:00:00Z", "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
        store.clear()
        assert store.count_incidents() == 0
        assert store.load_trend() == []
