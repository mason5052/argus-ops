"""Shared pytest fixtures for argus-ops tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus_ops.models import (
    Finding,
    FindingCategory,
    HealthSnapshot,
    InfraType,
    Severity,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def node_fixture_data():
    """Raw node data matching K8s collector output."""
    with open(FIXTURES_DIR / "k8s_nodes.json") as f:
        return json.load(f)


@pytest.fixture
def pod_fixture_data():
    """Raw pod data matching K8s collector output."""
    with open(FIXTURES_DIR / "k8s_pods.json") as f:
        return json.load(f)


@pytest.fixture
def node_snapshot(node_fixture_data):
    """HealthSnapshot with node data."""
    return HealthSnapshot(
        collector_name="kubernetes",
        infra_type=InfraType.KUBERNETES,
        target="k8s://nodes",
        data={"nodes": node_fixture_data},
        metrics={
            "nodes.total": float(len(node_fixture_data)),
            "nodes.ready": 2.0,
        },
    )


@pytest.fixture
def pod_snapshot(pod_fixture_data):
    """HealthSnapshot with pod data for the 'rpa' namespace."""
    rpa_pods = [p for p in pod_fixture_data if p["namespace"] == "rpa"]
    return HealthSnapshot(
        collector_name="kubernetes",
        infra_type=InfraType.KUBERNETES,
        target="k8s://rpa/pods",
        data={"pods": rpa_pods, "namespace": "rpa"},
        metrics={"pods.rpa.total": float(len(rpa_pods))},
    )


@pytest.fixture
def sample_finding():
    """A single sample finding for testing reporters and pipeline."""
    return Finding(
        finding_id="TEST-001",
        category=FindingCategory.POD_HEALTH,
        severity=Severity.HIGH,
        title="CrashLoopBackOff: rpa/crashloop-pod-xyz99/app",
        description="Container app is crash-looping with 12 restarts.",
        target="k8s://rpa/crashloop-pod-xyz99/app",
        infra_type=InfraType.KUBERNETES,
        evidence=["State: CrashLoopBackOff", "Restart count: 12"],
        metrics={"restart_count": 12},
    )


@pytest.fixture
def sample_findings(sample_finding):
    """Multiple findings of varying severity."""
    return [
        sample_finding,
        Finding(
            finding_id="TEST-002",
            category=FindingCategory.NODE_HEALTH,
            severity=Severity.CRITICAL,
            title="Node NotReady: worker-1-windows",
            description="Windows worker node is not ready.",
            target="k8s://node/worker-1-windows",
            infra_type=InfraType.KUBERNETES,
            evidence=["Ready status: False", "Reason: KubeletNotReady"],
        ),
        Finding(
            finding_id="TEST-003",
            category=FindingCategory.RESOURCE,
            severity=Severity.MEDIUM,
            title="No resource limits: default/no-limits-pod-jkl01/web",
            description="Container has no CPU or memory limits.",
            target="k8s://default/no-limits-pod-jkl01/web",
            infra_type=InfraType.KUBERNETES,
            evidence=["No limits: no-limits-pod-jkl01/web"],
        ),
    ]


@pytest.fixture
def default_config():
    """Default configuration dict for testing."""
    from argus_ops.config import load_config
    return load_config(config_path=None)
