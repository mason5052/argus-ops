"""Rule-based anomaly analyzers."""

from argus_ops.analyzers.node_health import NodeHealthAnalyzer
from argus_ops.analyzers.pod_health import PodHealthAnalyzer
from argus_ops.analyzers.resource import ResourceAnalyzer

ALL_ANALYZERS = [ResourceAnalyzer, PodHealthAnalyzer, NodeHealthAnalyzer]

__all__ = ["ResourceAnalyzer", "PodHealthAnalyzer", "NodeHealthAnalyzer", "ALL_ANALYZERS"]
