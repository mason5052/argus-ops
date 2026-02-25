"""Interactive approval gate with risk-level enforcement."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel

from argus_ops.audit.models import ApprovalRecord, RiskLevel
from argus_ops.healers.risk import (
    classify_risk,
    is_auto_approvable,
    is_blocked_in_auto,
    requires_reason,
)

logger = logging.getLogger(__name__)
console = Console()

_RISK_COLORS = {
    RiskLevel.low: "green",
    RiskLevel.medium: "yellow",
    RiskLevel.high: "red",
    RiskLevel.critical: "bold red",
}


class ApprovalGate:
    """Manages the approval flow for heal actions based on risk level.

    Args:
        actor: The authenticated username performing the action.
        auto_mode: If True, auto-approve low-risk actions.
    """

    def __init__(self, actor: str, auto_mode: bool = False) -> None:
        self._actor = actor
        self._auto_mode = auto_mode

    def request_approval(
        self,
        *,
        action: str,
        target: str,
        namespace: str = "",
        reason: str = "",
        command: str = "",
        risk_level: RiskLevel | None = None,
        dry_run: bool = False,
    ) -> ApprovalRecord:
        """Request approval for a heal action.

        Returns an ApprovalRecord with method='denied' if rejected.
        """
        if risk_level is None:
            risk_level = classify_risk(action, target, namespace)

        color = _RISK_COLORS.get(risk_level, "white")

        # Dry-run always proceeds (logged but not executed)
        if dry_run:
            return ApprovalRecord(
                method="dry_run",
                approved_by=self._actor,
                approved_at=datetime.now(timezone.utc),
                reason=reason,
            )

        # Critical actions blocked in auto mode
        if self._auto_mode and is_blocked_in_auto(risk_level):
            console.print(
                f"[bold red]BLOCKED[/bold red]: Action '{action}' on '{target}' is "
                f"[{color}]{risk_level.value}[/{color}] risk -- cannot auto-approve."
            )
            return ApprovalRecord(method="denied", reason="Critical risk blocked in auto mode")

        # Auto-approve low risk in auto mode
        if self._auto_mode and is_auto_approvable(risk_level):
            logger.info("Auto-approved: %s on %s (risk: %s)", action, target, risk_level.value)
            return ApprovalRecord(
                method="auto",
                approved_by="auto",
                approved_at=datetime.now(timezone.utc),
                reason=reason or "Auto-approved (low risk)",
            )

        # Interactive approval for everything else
        console.print()
        console.print(
            Panel(
                f"[bold]Action:[/bold] {action}\n"
                f"[bold]Target:[/bold] {target}"
                f"{f' (namespace: {namespace})' if namespace else ''}\n"
                f"[bold]Risk:[/bold] [{color}]{risk_level.value.upper()}[/{color}]\n"
                f"[bold]Command:[/bold] {command}\n"
                f"[bold]Reason:[/bold] {reason}",
                title="Approval Required",
                border_style=color,
            )
        )

        # High/critical risk requires a reason
        user_reason = reason
        if requires_reason(risk_level) and not reason:
            user_reason = click.prompt("Reason for this action (required for high risk)")
            if not user_reason.strip():
                console.print("[red]Reason required. Action denied.[/red]")
                return ApprovalRecord(method="denied", reason="No reason provided")

        approved = click.confirm("Approve this action?", default=False)
        if not approved:
            logger.info("User denied: %s on %s", action, target)
            return ApprovalRecord(method="denied", reason="User rejected")

        return ApprovalRecord(
            method="interactive",
            approved_by=self._actor,
            approved_at=datetime.now(timezone.utc),
            reason=user_reason or reason,
        )
