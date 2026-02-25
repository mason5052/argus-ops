"""Network policy analyzer: namespace coverage gaps, overly permissive policies."""

from __future__ import annotations

import logging
import uuid

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import Finding, FindingCategory, HealthSnapshot, InfraType, Severity

logger = logging.getLogger(__name__)

# System namespaces to exclude from policy checks
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class NetworkPolicyAnalyzer(BaseAnalyzer):
    """Detects network policy gaps in the cluster.

    Checks:
    - Namespaces without any NetworkPolicy
    - Overly permissive policies (allow all ingress/egress)
    """

    @property
    def name(self) -> str:
        return "network_policy"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NETWORK_POLICY

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snap in snapshots:
            if snap.collector_name != "kubernetes":
                continue

            data = snap.data

            # Collect all namespaces
            namespaces = data.get("namespaces", [])
            network_policies = data.get("network_policies", [])

            # Build set of namespaces that have at least one NetworkPolicy
            covered_namespaces: set[str] = set()
            for np in network_policies:
                ns = np.get("namespace", "")
                if ns:
                    covered_namespaces.add(ns)

                # Check for overly permissive policies
                np_name = np.get("name", "")
                ingress_rules = np.get("ingress", [])
                egress_rules = np.get("egress", [])

                # Empty ingress/egress with policy types means "allow all"
                policy_types = np.get("policy_types", [])
                if "Ingress" in policy_types and not ingress_rules:
                    findings.append(
                        Finding(
                            finding_id=f"NETPOL-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.NETWORK_POLICY,
                            severity=Severity.MEDIUM,
                            title=f"Permissive ingress: {np_name}",
                            description=(
                                f"NetworkPolicy '{np_name}' in namespace '{ns}' "
                                "declares Ingress policy type but has no ingress rules, "
                                "which blocks all ingress traffic."
                            ),
                            target=f"{ns}/networkpolicy/{np_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                f"Policy types: {policy_types}",
                                "Ingress rules: none (deny all)",
                            ],
                        )
                    )

            # Check for namespaces without any NetworkPolicy
            for ns_info in namespaces:
                ns_name = ns_info if isinstance(ns_info, str) else ns_info.get("name", "")
                if ns_name in _SYSTEM_NAMESPACES:
                    continue
                if ns_name not in covered_namespaces:
                    findings.append(
                        Finding(
                            finding_id=f"NETPOL-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.NETWORK_POLICY,
                            severity=Severity.LOW,
                            title=f"No NetworkPolicy: namespace '{ns_name}'",
                            description=(
                                f"Namespace '{ns_name}' has no NetworkPolicy. "
                                "All pod-to-pod traffic is allowed by default."
                            ),
                            target=f"namespace/{ns_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=["NetworkPolicies: 0"],
                        )
                    )

        # Summary finding if many namespaces are uncovered
        total_ns = len([
            ns for ns in (
                data.get("namespaces", []) if snapshots else []
            )
            if (ns if isinstance(ns, str) else ns.get("name", "")) not in _SYSTEM_NAMESPACES
        ]) if snapshots else 0

        uncovered = total_ns - len(covered_namespaces)
        if total_ns > 0 and uncovered > total_ns * 0.5:
            findings.append(
                Finding(
                    finding_id=f"NETPOL-{uuid.uuid4().hex[:8]}",
                    category=FindingCategory.NETWORK_POLICY,
                    severity=Severity.MEDIUM,
                    title=f"Network policy coverage gap: {uncovered}/{total_ns} namespaces unprotected",
                    description=(
                        f"{uncovered} out of {total_ns} namespaces have no NetworkPolicy. "
                        "This represents a significant network segmentation gap."
                    ),
                    target="cluster",
                    infra_type=InfraType.KUBERNETES,
                    evidence=[
                        f"Covered: {len(covered_namespaces)}",
                        f"Uncovered: {uncovered}",
                        f"Total: {total_ns}",
                    ],
                )
            )

        return findings
