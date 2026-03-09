"""Rich console reporter for findings and diagnoses."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus_ops.models import Diagnosis, Finding, Incident, Severity

console = Console()

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.INFO: "blue",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange1",
    Severity.CRITICAL: "red",
}

_SEVERITY_ICON: dict[Severity, str] = {
    Severity.INFO: "[blue]i[/]",
    Severity.LOW: "[cyan]L[/]",
    Severity.MEDIUM: "[yellow]M[/]",
    Severity.HIGH: "[orange1]H[/]",
    Severity.CRITICAL: "[red]C[/]",
}


def print_findings(findings: list[Finding], title: str = "Scan Results") -> None:
    """Print findings as a Rich table."""
    if not findings:
        console.print(
            Panel("[green]No findings detected. Infrastructure looks healthy.[/]", title=title)
        )
        return

    table = Table(
        title=title,
        show_header=True,
        header_style="bold",
        expand=True,
        show_lines=False,
    )
    table.add_column("Sev", width=4, no_wrap=True)
    table.add_column("Category", width=12, no_wrap=True)
    table.add_column("Title", min_width=30)
    table.add_column("Target", min_width=25)

    # Sort by severity (most critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    for finding in sorted_findings:
        color = _SEVERITY_COLOR[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value[:1].upper()}[/]",
            finding.category.value.replace("_", " "),
            finding.title,
            finding.target,
        )

    console.print(table)
    _print_finding_summary(findings)


def _print_finding_summary(findings: list[Finding]) -> None:
    """Print a one-line summary of findings by severity."""
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if sev in counts:
            color = _SEVERITY_COLOR[sev]
            parts.append(f"[{color}]{counts[sev]} {sev.value}[/]")

    total = len(findings)
    summary = f"[bold]{total} finding(s)[/]: " + "  ".join(parts)
    console.print(summary)
    console.print()


def print_finding_detail(finding: Finding) -> None:
    """Print detailed view of a single finding."""
    color = _SEVERITY_COLOR[finding.severity]
    content = Text()
    content.append(f"{finding.description}\n\n", style="default")

    if finding.evidence:
        content.append("Evidence:\n", style="bold")
        for e in finding.evidence:
            content.append(f"  - {e}\n")

    if finding.metrics:
        content.append("\nMetrics:\n", style="bold")
        for k, v in finding.metrics.items():
            content.append(f"  {k}: {v}\n")

    console.print(Panel(
        content,
        title=f"[{color}][{finding.severity.value.upper()}] {finding.title}[/]",
        subtitle=f"ID: {finding.finding_id}  |  Target: {finding.target}",
        border_style=color,
    ))


def print_diagnosis(diagnosis: Diagnosis) -> None:
    """Print AI diagnosis as a Rich panel."""
    content = Text()
    content.append("Root Cause\n", style="bold underline")
    content.append(f"{diagnosis.root_cause}\n\n")

    content.append("Explanation\n", style="bold underline")
    content.append(f"{diagnosis.explanation}\n\n")

    if diagnosis.recommendations:
        content.append("Recommendations\n", style="bold underline")
        for i, rec in enumerate(diagnosis.recommendations, 1):
            content.append(f"  {i}. {rec}\n")
        content.append("\n")

    if diagnosis.related_resources:
        content.append("Related Resources\n", style="bold underline")
        for resource in diagnosis.related_resources:
            content.append(f"  - {resource}\n")
        content.append("\n")

    confidence_color = "green" if diagnosis.confidence >= 0.7 else "yellow"
    meta = (
        f"Model: {diagnosis.model_used or 'N/A'}  |  "
        f"Confidence: [{confidence_color}]{diagnosis.confidence:.0%}[/]  |  "
        f"Tokens: {diagnosis.tokens_used}  |  "
        f"Cost: ${diagnosis.cost_usd:.4f}"
    )

    console.print(Panel(
        content,
        title="[bold blue]AI Diagnosis[/]",
        subtitle=meta,
        border_style="blue",
    ))


def print_incidents(incidents: list[Incident]) -> None:
    """Print a summary of incidents."""
    for incident in incidents:
        print_findings(incident.findings, title=f"Incident {incident.incident_id}")
        if incident.diagnosis:
            print_diagnosis(incident.diagnosis)


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[red]Error:[/] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]{message}[/]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[dim]{message}[/]")
