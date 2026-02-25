"""Rule-based anomaly analyzers."""

from argus_ops.analyzers.configuration import ConfigurationAnalyzer
from argus_ops.analyzers.cronjob import CronJobAnalyzer
from argus_ops.analyzers.network_policy import NetworkPolicyAnalyzer
from argus_ops.analyzers.node_health import NodeHealthAnalyzer
from argus_ops.analyzers.pod_health import PodHealthAnalyzer
from argus_ops.analyzers.resource import ResourceAnalyzer
from argus_ops.analyzers.security import SecurityAnalyzer
from argus_ops.analyzers.storage import StorageAnalyzer

ALL_ANALYZERS = [
    ResourceAnalyzer,
    PodHealthAnalyzer,
    NodeHealthAnalyzer,
    StorageAnalyzer,
    CronJobAnalyzer,
    NetworkPolicyAnalyzer,
    SecurityAnalyzer,
    ConfigurationAnalyzer,
]

__all__ = [
    "ResourceAnalyzer",
    "PodHealthAnalyzer",
    "NodeHealthAnalyzer",
    "StorageAnalyzer",
    "CronJobAnalyzer",
    "NetworkPolicyAnalyzer",
    "SecurityAnalyzer",
    "ConfigurationAnalyzer",
    "ALL_ANALYZERS",
]
