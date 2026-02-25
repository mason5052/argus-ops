"""CLI viewer for audit records using Rich tables + CSV export."""

from __future__ import annotations

import logging
from datetime import date

from rich.console import Console
from rich.table import Table

from argus_ops.audit.correlator import AuditCorrelator
from argus_ops.audit.k8s_audit import K8sAuditCollector
from argus_ops.audit.logger import AuditLogger
from argus_ops.audit.models import AuditRecord, K8sAuditEvent, RiskLevel

logger = logging.getLogger(__name__)
console = Console()

_RISK_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


def print_audit_records(records: list[AuditRecord], title: str = "Audit Log") -> None:
    """Render Layer 1 audit records as a Rich table."""
    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Actor", width=15)
    table.add_column("Source", width=8)
    table.add_column("Action", width=25)
    table.add_column("Target", width=35)
    table.add_column("Risk", width=8)
    table.add_column("Result", width=10)

    for rec in records:
        ts = rec.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        risk_color = _RISK_COLORS.get(rec.risk_level.value, "white")
        result_status = rec.result.get("status", "")
        result_style = "green" if result_status == "success" else "red"
        dry = " (dry)" if rec.dry_run else ""
        table.add_row(
            ts,
            rec.actor,
            rec.source,
            rec.action,
            rec.target,
            f"[{risk_color}]{rec.risk_level.value}[/{risk_color}]",
            f"[{result_style}]{result_status}{dry}[/{result_style}]",
        )

    console.print(table)
    console.print(f"  Total: {len(records)} record(s)")


def print_k8s_audit_events(
    events: list[K8sAuditEvent], title: str = "K8s Cluster Audit"
) -> None:
    """Render Layer 2 K8s audit events as a Rich table."""
    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("Time", style="dim", width=19)
    table.add_column("User", width=20)
    table.add_column("Verb", width=10)
    table.add_column("Resource", width=20)
    table.add_column("Name", width=25)
    table.add_column("Namespace", width=15)

    for ev in events:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        matched = " *" if ev.argus_ops_record_id else ""
        table.add_row(
            ts,
            ev.user,
            ev.verb,
            ev.resource_kind,
            ev.resource_name + matched,
            ev.namespace,
        )

    console.print(table)
    console.print(f"  Total: {len(events)} event(s)  (* = matched to Argus-Ops action)")


def print_combined_audit(entries: list[dict], title: str = "Combined Audit") -> None:
    """Render combined Layer 1 + Layer 2 audit entries."""
    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Layer", width=6)
    table.add_column("Source", width=12)
    table.add_column("Actor", width=15)
    table.add_column("Action", width=20)
    table.add_column("Target", width=35)
    table.add_column("Risk", width=8)

    for entry in entries:
        ts = entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        layer = f"L{entry['layer']}"
        layer_style = "cyan" if entry["layer"] == 1 else "dim"
        risk = entry.get("risk_level", "")
        risk_color = _RISK_COLORS.get(risk, "dim")
        table.add_row(
            ts,
            f"[{layer_style}]{layer}[/{layer_style}]",
            entry["source"],
            entry["actor"],
            entry["action"],
            entry["target"],
            f"[{risk_color}]{risk}[/{risk_color}]" if risk else "",
        )

    console.print(table)
    console.print(f"  Total: {len(entries)} entries")


def print_drift_events(events: list[K8sAuditEvent]) -> None:
    """Render drift events (changes NOT made through Argus-Ops)."""
    if not events:
        console.print("[green]No drift detected -- all changes were made through Argus-Ops.[/green]")
        return
    console.print(
        f"[yellow]Drift detected: {len(events)} change(s) made outside Argus-Ops[/yellow]"
    )
    print_k8s_audit_events(events, title="Drift Detection (External Changes)")
