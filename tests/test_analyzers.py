"""Tests for rule-based anomaly analyzers."""

from __future__ import annotations

from argus_ops.analyzers.node_health import NodeHealthAnalyzer
from argus_ops.analyzers.pod_health import PodHealthAnalyzer
from argus_ops.analyzers.resource import ResourceAnalyzer
from argus_ops.models import FindingCategory, InfraType, Severity


class TestNodeHealthAnalyzer:
    """Tests for NodeHealthAnalyzer."""

    def setup_method(self):
        self.analyzer = NodeHealthAnalyzer()

    def test_detects_not_ready_node(self, node_snapshot):
        findings = self.analyzer.analyze([node_snapshot])
        not_ready = [f for f in findings if "NotReady" in f.title]
        assert len(not_ready) >= 1
        assert not_ready[0].target == "k8s://node/worker-1-windows"
        assert not_ready[0].severity in (Severity.CRITICAL, Severity.HIGH)

    def test_detects_memory_pressure(self, node_snapshot):
        findings = self.analyzer.analyze([node_snapshot])
        pressure = [f for f in findings if "MemoryPressure" in f.title]
        assert len(pressure) == 1
        assert "jetson" in pressure[0].target
        assert pressure[0].severity == Severity.HIGH

    def test_no_findings_for_healthy_nodes(self, node_fixture_data):
        from argus_ops.models import HealthSnapshot

        healthy_nodes = [
            n for n in node_fixture_data
            if n["conditions"].get("Ready", {}).get("status") == "True"
            and n["conditions"].get("MemoryPressure", {}).get("status") != "True"
        ]
        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://nodes",
            data={"nodes": healthy_nodes},
        )
        findings = self.analyzer.analyze([snapshot])
        assert all(f.category == FindingCategory.NODE_HEALTH for f in findings)
        assert not any("NotReady" in f.title for f in findings)
        assert not any("MemoryPressure" in f.title for f in findings)

    def test_skips_non_k8s_snapshots(self, node_snapshot):
        from argus_ops.models import HealthSnapshot, InfraType

        ssh_snapshot = HealthSnapshot(
            collector_name="ssh",
            infra_type=InfraType.SSH_HOST,
            target="ssh://10.1.1.56",
            data={"nodes": node_snapshot.data["nodes"]},
        )
        findings = self.analyzer.analyze([ssh_snapshot])
        assert findings == []

    def test_detects_cordoned_node(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://nodes",
            data={"nodes": [{
                "name": "drained-node",
                "conditions": {
                    "Ready": {"status": "True", "reason": "KubeletReady", "message": ""},
                    "MemoryPressure": {"status": "False", "reason": "", "message": ""},
                    "DiskPressure": {"status": "False", "reason": "", "message": ""},
                    "PIDPressure": {"status": "False", "reason": "", "message": ""},
                },
                "os": "linux",
                "arch": "amd64",
                "unschedulable": True,
                "taints": [],
                "allocatable": {},
                "capacity": {},
                "labels": {},
            }]},
        )
        findings = self.analyzer.analyze([snapshot])
        cordoned = [f for f in findings if "cordoned" in f.title.lower()]
        assert len(cordoned) == 1


class TestPodHealthAnalyzer:
    """Tests for PodHealthAnalyzer."""

    def setup_method(self):
        self.analyzer = PodHealthAnalyzer()

    def test_detects_crashloopbackoff(self, pod_snapshot):
        findings = self.analyzer.analyze([pod_snapshot])
        crashloop = [f for f in findings if "CrashLoopBackOff" in f.title]
        assert len(crashloop) == 1
        assert crashloop[0].severity == Severity.HIGH
        assert "crashloop-pod-xyz99" in crashloop[0].target

    def test_detects_oomkilled(self, pod_snapshot):
        findings = self.analyzer.analyze([pod_snapshot])
        oom = [f for f in findings if "OOMKilled" in f.title]
        assert len(oom) == 1
        assert oom[0].severity == Severity.HIGH
        assert "oom-pod-def45" in oom[0].target

    def test_detects_pending_pod(self, pod_snapshot):
        findings = self.analyzer.analyze([pod_snapshot])
        pending = [f for f in findings if "Pending" in f.title or "Pending" in f.description]
        assert len(pending) >= 1

    def test_no_findings_for_healthy_running_pod(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://default/pods",
            data={
                "namespace": "default",
                "pods": [{
                    "name": "healthy-pod",
                    "namespace": "default",
                    "phase": "Running",
                    "node_name": "worker-2",
                    "creation_timestamp": "2026-02-22T00:00:00+00:00",
                    "containers": [{
                        "name": "app",
                        "ready": True,
                        "restart_count": 0,
                        "image": "nginx:latest",
                        "state": {"state": "running"},
                    }],
                    "resources": {},
                }],
            },
        )
        findings = self.analyzer.analyze([snapshot])
        assert findings == []

    def test_excessive_restarts_threshold(self):
        from argus_ops.models import HealthSnapshot

        analyzer = PodHealthAnalyzer(config={"crashloop_restart_threshold": 3})
        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://rpa/pods",
            data={
                "namespace": "rpa",
                "pods": [{
                    "name": "flappy-pod",
                    "namespace": "rpa",
                    "phase": "Running",
                    "node_name": "worker-2",
                    "creation_timestamp": "2026-02-22T00:00:00+00:00",
                    "containers": [{
                        "name": "app",
                        "ready": True,
                        "restart_count": 5,
                        "image": "app:latest",
                        "state": {"state": "running"},
                    }],
                    "resources": {},
                }],
            },
        )
        findings = analyzer.analyze([snapshot])
        excessive = [f for f in findings if "restart" in f.title.lower()]
        assert len(excessive) >= 1

    def test_imagepullbackoff(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://default/pods",
            data={
                "namespace": "default",
                "pods": [{
                    "name": "bad-image-pod",
                    "namespace": "default",
                    "phase": "Pending",
                    "node_name": "worker-2",
                    "creation_timestamp": "2026-02-22T00:00:00+00:00",
                    "containers": [{
                        "name": "app",
                        "ready": False,
                        "restart_count": 0,
                        "image": "nonexistent:latest",
                        "state": {
                            "state": "waiting",
                            "waiting_reason": "ImagePullBackOff",
                            "waiting_message": "Back-off pulling image",
                        },
                    }],
                    "resources": {},
                }],
            },
        )
        findings = self.analyzer.analyze([snapshot])
        image_pull = [f for f in findings if "image pull" in f.title.lower()]
        assert len(image_pull) == 1
        assert image_pull[0].severity == Severity.HIGH


class TestResourceAnalyzer:
    """Tests for ResourceAnalyzer."""

    def setup_method(self):
        self.analyzer = ResourceAnalyzer()

    def test_detects_no_resource_limits(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://default/pods",
            data={
                "namespace": "default",
                "pods": [
                    {
                        "name": "unlimited-pod",
                        "namespace": "default",
                        "phase": "Running",
                        "resources": {
                            "app": {"requests": {}, "limits": {}}
                        },
                    }
                ],
            },
        )
        findings = self.analyzer.analyze([snapshot])
        limit_findings = [f for f in findings if "without resource limits" in f.title]
        assert len(limit_findings) == 1
        assert limit_findings[0].severity == Severity.MEDIUM

    def test_no_findings_when_limits_set(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="kubernetes",
            infra_type=InfraType.KUBERNETES,
            target="k8s://default/pods",
            data={
                "namespace": "default",
                "pods": [
                    {
                        "name": "bounded-pod",
                        "namespace": "default",
                        "phase": "Running",
                        "resources": {
                            "app": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"cpu": "500m", "memory": "256Mi"},
                            }
                        },
                    }
                ],
            },
        )
        findings = self.analyzer.analyze([snapshot])
        limit_findings = [f for f in findings if "without resource limits" in f.title]
        assert len(limit_findings) == 0

    def test_parse_memory_units(self):
        parse = ResourceAnalyzer._parse_memory
        assert parse("1Gi") == 1024 ** 3
        assert parse("512Mi") == 512 * 1024 ** 2
        assert parse("4096Ki") == 4096 * 1024
        assert parse("0") == 0.0
        assert parse("") == 0.0

    def test_skips_non_k8s_snapshots(self):
        from argus_ops.models import HealthSnapshot

        snapshot = HealthSnapshot(
            collector_name="ssh",
            infra_type=InfraType.SSH_HOST,
            target="ssh://10.1.1.56",
            data={},
        )
        findings = self.analyzer.analyze([snapshot])
        assert findings == []
