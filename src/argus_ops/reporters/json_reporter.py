"""JSON reporter for findings and diagnoses."""

from __future__ import annotations

import json

from argus_ops.models import Diagnosis, Finding, Incident


def findings_to_json(findings: list[Finding], indent: int = 2) -> str:
    """Serialize findings to a JSON string."""
    data = [finding_to_dict(f) for f in findings]
    return json.dumps(data, indent=indent, default=str)


def diagnosis_to_json(diagnosis: Diagnosis, indent: int = 2) -> str:
    """Serialize a diagnosis to a JSON string."""
    return json.dumps(diagnosis_to_dict(diagnosis), indent=indent, default=str)


def incident_to_json(incident: Incident, indent: int = 2) -> str:
    """Serialize an incident (findings + diagnosis) to a JSON string."""
    data = {
        "incident_id": incident.incident_id,
        "status": incident.status,
        "max_severity": incident.max_severity.value,
        "created_at": incident.created_at.isoformat(),
        "findings": [finding_to_dict(f) for f in incident.findings],
        "diagnosis": diagnosis_to_dict(incident.diagnosis) if incident.diagnosis else None,
    }
    return json.dumps(data, indent=indent, default=str)


def finding_to_dict(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "category": f.category.value,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "target": f.target,
        "infra_type": f.infra_type.value,
        "evidence": f.evidence,
        "metrics": f.metrics,
        "timestamp": f.timestamp.isoformat(),
    }


def diagnosis_to_dict(d: Diagnosis) -> dict:
    return {
        "diagnosis_id": d.diagnosis_id,
        "finding_ids": d.finding_ids,
        "root_cause": d.root_cause,
        "explanation": d.explanation,
        "confidence": d.confidence,
        "recommendations": d.recommendations,
        "related_resources": d.related_resources,
        "model_used": d.model_used,
        "tokens_used": d.tokens_used,
        "cost_usd": d.cost_usd,
        "timestamp": d.timestamp.isoformat(),
    }
