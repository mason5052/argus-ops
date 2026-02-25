"""Tests for the K8s healer, risk classification, and approval gate."""

from __future__ import annotations

import pytest

from argus_ops.audit.models import RiskLevel
from argus_ops.healers.risk import (
    classify_risk,
    is_auto_approvable,
    is_blocked_in_auto,
    requires_reason,
)


class TestRiskClassification:
    def test_low_risk_actions(self):
        assert classify_risk("restart_pod") == RiskLevel.low
        assert classify_risk("cleanup_completed_jobs") == RiskLevel.low
        assert classify_risk("suspend_cronjob") == RiskLevel.low

    def test_medium_risk_actions(self):
        assert classify_risk("patch_resource_limits") == RiskLevel.medium
        assert classify_risk("scale_deployment") == RiskLevel.medium

    def test_high_risk_actions(self):
        assert classify_risk("rollback_deployment") == RiskLevel.high
        assert classify_risk("drain_node") == RiskLevel.high

    def test_critical_risk_actions(self):
        assert classify_risk("delete_node") == RiskLevel.critical
        assert classify_risk("delete_namespace") == RiskLevel.critical

    def test_unknown_action_defaults_to_medium(self):
        assert classify_risk("unknown_action") == RiskLevel.medium

    def test_kube_system_elevates_risk(self):
        # restart_pod is normally low, but in kube-system it becomes critical
        risk = classify_risk("restart_pod", namespace="kube-system")
        assert risk == RiskLevel.critical

    def test_auto_approvable(self):
        assert is_auto_approvable(RiskLevel.low) is True
        assert is_auto_approvable(RiskLevel.medium) is False
        assert is_auto_approvable(RiskLevel.high) is False

    def test_requires_reason(self):
        assert requires_reason(RiskLevel.low) is False
        assert requires_reason(RiskLevel.medium) is False
        assert requires_reason(RiskLevel.high) is True
        assert requires_reason(RiskLevel.critical) is True

    def test_blocked_in_auto(self):
        assert is_blocked_in_auto(RiskLevel.critical) is True
        assert is_blocked_in_auto(RiskLevel.high) is False
        assert is_blocked_in_auto(RiskLevel.low) is False
