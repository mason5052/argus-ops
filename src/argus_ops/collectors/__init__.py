"""Infrastructure data collectors."""

from argus_ops.collectors.k8s import KubernetesCollector
from argus_ops.collectors.local import (
    AWSCollector,
    DockerCollector,
    GitHubCollector,
    GitRepoCollector,
    HostCollector,
    TerraformCollector,
)

__all__ = [
    "KubernetesCollector",
    "HostCollector",
    "DockerCollector",
    "GitRepoCollector",
    "TerraformCollector",
    "GitHubCollector",
    "AWSCollector",
]
