"""Tests for output reporters."""

from __future__ import annotations

import json

from argus_ops.models import Diagnosis, Incident
from argus_ops.reporters.json_reporter import (
    findings_to_json,
    incident_to_json,
)


class TestJsonReporter:
    def test_findings_to_json_valid(self, sample_findings):
        result = findings_to_json(sample_findings)
        parsed = json.loads(result)
        assert len(parsed) == len(sample_findings)
        assert parsed[0]["finding_id"] == "TEST-001"

    def test_findings_to_json_empty(self):
        result = findings_to_json([])
        parsed = json.loads(result)
        assert parsed == []

    def test_findings_json_has_required_fields(self, sample_finding):
        result = findings_to_json([sample_finding])
        parsed = json.loads(result)
        assert len(parsed) == 1
        entry = parsed[0]
        for field in ["finding_id", "severity", "title", "target", "category", "infra_type"]:
            assert field in entry, f"Missing field: {field}"

    def test_incident_to_json_with_diagnosis(self, sample_finding):
        diagnosis = Diagnosis(
            diagnosis_id="DIAG-001",
            root_cause="Test root cause",
            explanation="Test explanation",
            confidence=0.85,
            model_used="gpt-4o-mini",
            tokens_used=500,
            cost_usd=0.0001,
        )
        incident = Incident(
            incident_id="INC-001",
            findings=[sample_finding],
            diagnosis=diagnosis,
        )
        result = incident_to_json(incident)
        parsed = json.loads(result)

        assert parsed["incident_id"] == "INC-001"
        assert parsed["diagnosis"]["root_cause"] == "Test root cause"
        assert parsed["diagnosis"]["confidence"] == 0.85
        assert len(parsed["findings"]) == 1

    def test_incident_to_json_without_diagnosis(self, sample_finding):
        incident = Incident(
            incident_id="INC-002",
            findings=[sample_finding],
        )
        result = incident_to_json(incident)
        parsed = json.loads(result)
        assert parsed["diagnosis"] is None
