"""Tests for the 5 new analyzers (storage, cronjob, network_policy, security, configuration)."""

from __future__ import annotations

import pytest

from argus_ops.analyzers.configuration import ConfigurationAnalyzer
from argus_ops.analyzers.cronjob import CronJobAnalyzer
from argus_ops.analyzers.network_policy import NetworkPolicyAnalyzer
from argus_ops.analyzers.security import SecurityAnalyzer
from argus_ops.analyzers.storage import StorageAnalyzer
from argus_ops.models import FindingCategory, HealthSnapshot, InfraType


def _make_snapshot(data: dict) -> HealthSnapshot:
    return HealthSnapshot(
        collector_name="kubernetes",
        infra_type=InfraType.KUBERNETES,
        target="k8s://test",
        data=data,
    )


# ---------------------------------------------------------------------------
# StorageAnalyzer
# ---------------------------------------------------------------------------

class TestStorageAnalyzer:
    def test_orphaned_pv(self):
        snap = _make_snapshot({
            "persistent_volumes": [
                {"name": "old-pv", "phase": "Released", "capacity": {"storage": "10Gi"}},
                {"name": "active-pv", "phase": "Bound", "capacity": {"storage": "5Gi"}},
            ],
        })
        findings = StorageAnalyzer().analyze([snap])
        assert len(findings) == 1
        assert "Orphaned" in findings[0].title
        assert findings[0].category == FindingCategory.STORAGE

    def test_failed_pv(self):
        snap = _make_snapshot({
            "persistent_volumes": [
                {"name": "bad-pv", "phase": "Failed", "capacity": {"storage": "1Gi"}},
            ],
        })
        findings = StorageAnalyzer().analyze([snap])
        assert len(findings) == 1
        assert "Failed" in findings[0].title

    def test_no_issues(self):
        snap = _make_snapshot({
            "persistent_volumes": [
                {"name": "good-pv", "phase": "Bound", "capacity": {"storage": "5Gi"}},
            ],
        })
        findings = StorageAnalyzer().analyze([snap])
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CronJobAnalyzer
# ---------------------------------------------------------------------------

class TestCronJobAnalyzer:
    def test_schedule_conflict(self):
        snap = _make_snapshot({
            "cronjobs": [
                {"name": "job1", "namespace": "test", "schedule": "0 0 * * *", "suspended": False},
                {"name": "job2", "namespace": "test", "schedule": "0 0 * * *", "suspended": False},
                {"name": "job3", "namespace": "test", "schedule": "0 0 * * *", "suspended": False},
            ],
            "pods": [],
        })
        findings = CronJobAnalyzer().analyze([snap])
        conflict_findings = [f for f in findings if "conflict" in f.title.lower()]
        assert len(conflict_findings) == 1
        assert "3 CronJobs" in conflict_findings[0].title

    def test_no_history_limit(self):
        snap = _make_snapshot({
            "cronjobs": [
                {
                    "name": "no-hist",
                    "namespace": "test",
                    "schedule": "*/5 * * * *",
                    "suspended": False,
                    "failed_jobs_history_limit": 0,
                },
            ],
            "pods": [],
        })
        findings = CronJobAnalyzer().analyze([snap])
        hist_findings = [f for f in findings if "history" in f.title.lower()]
        assert len(hist_findings) == 1

    def test_suspended_cronjob(self):
        snap = _make_snapshot({
            "cronjobs": [
                {"name": "paused", "namespace": "test", "schedule": "0 3 * * *", "suspended": True},
            ],
            "pods": [],
        })
        findings = CronJobAnalyzer().analyze([snap])
        suspended = [f for f in findings if "Suspended" in f.title]
        assert len(suspended) == 1


# ---------------------------------------------------------------------------
# NetworkPolicyAnalyzer
# ---------------------------------------------------------------------------

class TestNetworkPolicyAnalyzer:
    def test_namespace_without_policy(self):
        snap = _make_snapshot({
            "namespaces": [{"name": "unprotected"}, {"name": "protected"}],
            "network_policies": [
                {"name": "allow-web", "namespace": "protected", "policy_types": ["Ingress"]},
            ],
        })
        findings = NetworkPolicyAnalyzer().analyze([snap])
        no_policy = [f for f in findings if "No NetworkPolicy" in f.title]
        assert len(no_policy) >= 1
        assert "unprotected" in no_policy[0].title

    def test_system_namespaces_excluded(self):
        snap = _make_snapshot({
            "namespaces": [{"name": "kube-system"}, {"name": "kube-public"}],
            "network_policies": [],
        })
        findings = NetworkPolicyAnalyzer().analyze([snap])
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# SecurityAnalyzer
# ---------------------------------------------------------------------------

class TestSecurityAnalyzer:
    def test_default_service_account(self):
        snap = _make_snapshot({
            "pods": [
                {"name": "app", "namespace": "default", "service_account": "default", "containers": []},
            ],
            "namespaces": [{"name": "default"}],
            "resource_quotas": [],
        })
        findings = SecurityAnalyzer().analyze([snap])
        sa_findings = [f for f in findings if "Default ServiceAccount" in f.title]
        assert len(sa_findings) == 1

    def test_privileged_container(self):
        snap = _make_snapshot({
            "pods": [
                {
                    "name": "priv-pod",
                    "namespace": "test",
                    "service_account": "custom-sa",
                    "containers": [
                        {"name": "priv", "security_context": {"privileged": True}},
                    ],
                },
            ],
            "namespaces": [{"name": "test"}],
            "resource_quotas": [],
        })
        findings = SecurityAnalyzer().analyze([snap])
        priv = [f for f in findings if "Privileged" in f.title]
        assert len(priv) == 1

    def test_no_resource_quota(self):
        snap = _make_snapshot({
            "pods": [],
            "namespaces": [{"name": "no-quota"}],
            "resource_quotas": [],
        })
        findings = SecurityAnalyzer().analyze([snap])
        quota = [f for f in findings if "ResourceQuota" in f.title]
        assert len(quota) == 1


# ---------------------------------------------------------------------------
# ConfigurationAnalyzer
# ---------------------------------------------------------------------------

class TestConfigurationAnalyzer:
    def test_missing_metrics_server(self):
        snap = _make_snapshot({
            "deployments": [{"name": "nginx"}],
            "pods": [{"name": "nginx-pod"}],
            "nodes": [],
        })
        findings = ConfigurationAnalyzer().analyze([snap])
        ms = [f for f in findings if "metrics-server" in f.title.lower()]
        assert len(ms) == 1

    def test_metrics_server_present(self):
        snap = _make_snapshot({
            "deployments": [{"name": "metrics-server"}],
            "pods": [],
            "nodes": [],
        })
        findings = ConfigurationAnalyzer().analyze([snap])
        ms = [f for f in findings if "metrics-server" in f.title.lower()]
        assert len(ms) == 0

    def test_mixed_runtimes(self):
        snap = _make_snapshot({
            "deployments": [{"name": "metrics-server"}],
            "pods": [],
            "nodes": [
                {"name": "node1", "container_runtime": "containerd://1.7.0"},
                {"name": "node2", "container_runtime": "containerd://2.1.0"},
            ],
        })
        findings = ConfigurationAnalyzer().analyze([snap])
        runtime = [f for f in findings if "runtime" in f.title.lower()]
        assert len(runtime) == 1

    def test_workload_imbalance(self):
        snap = _make_snapshot({
            "deployments": [{"name": "metrics-server"}],
            "pods": [
                {"name": f"pod-{i}", "node_name": "heavy-node"} for i in range(30)
            ] + [
                {"name": "lonely-pod", "node_name": "light-node"},
            ],
            "nodes": [
                {"name": "heavy-node"},
                {"name": "light-node"},
            ],
        })
        findings = ConfigurationAnalyzer().analyze([snap])
        imbalance = [f for f in findings if "imbalance" in f.title.lower()]
        assert len(imbalance) == 1
        assert "heavy-node" in imbalance[0].title
