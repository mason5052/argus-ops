"""Risk classification engine for K8s heal operations."""

from __future__ import annotations

from argus_ops.audit.models import RiskLevel

# Action -> default risk level mapping
_ACTION_RISK: dict[str, RiskLevel] = {
    # Low risk (auto-approvable)
    "restart_pod": RiskLevel.low,
    "cleanup_completed_jobs": RiskLevel.low,
    "suspend_cronjob": RiskLevel.low,
    "delete_completed_pod": RiskLevel.low,
    # Medium risk (requires confirmation)
    "patch_resource_limits": RiskLevel.medium,
    "scale_deployment": RiskLevel.medium,
    "resume_cronjob": RiskLevel.medium,
    "patch_cronjob_schedule": RiskLevel.medium,
    # High risk (requires explicit approval + reason)
    "rollback_deployment": RiskLevel.high,
    "drain_node": RiskLevel.high,
    "uncordon_node": RiskLevel.high,
    "delete_pv": RiskLevel.high,
    "delete_pvc": RiskLevel.high,
    # Critical (blocked in --auto mode)
    "delete_node": RiskLevel.critical,
    "delete_namespace": RiskLevel.critical,
    "delete_deployment": RiskLevel.critical,
    "cordon_node": RiskLevel.high,
}

# Target patterns that elevate risk (namespace or resource name patterns)
_ELEVATED_TARGETS: dict[str, RiskLevel] = {
    "kube-system": RiskLevel.critical,
    "kube-public": RiskLevel.critical,
    "monitoring": RiskLevel.high,
    "ingress": RiskLevel.high,
}


def classify_risk(action: str, target: str = "", namespace: str = "") -> RiskLevel:
    """Classify the risk level of a heal action.

    Args:
        action: The action identifier (e.g., 'restart_pod', 'drain_node').
        target: The target resource name.
        namespace: The target namespace.

    Returns:
        The computed risk level.
    """
    base_risk = _ACTION_RISK.get(action, RiskLevel.medium)

    # Elevate risk based on target namespace
    ns_lower = namespace.lower()
    for pattern, elevated in _ELEVATED_TARGETS.items():
        if pattern in ns_lower and elevated > base_risk:
            base_risk = elevated

    return base_risk


def is_auto_approvable(risk: RiskLevel) -> bool:
    """Return True if the action can be auto-approved (low risk only)."""
    return risk == RiskLevel.low


def requires_reason(risk: RiskLevel) -> bool:
    """Return True if the action requires an explicit reason from the user."""
    return risk >= RiskLevel.high


def is_blocked_in_auto(risk: RiskLevel) -> bool:
    """Return True if the action cannot run in --auto mode."""
    return risk == RiskLevel.critical
